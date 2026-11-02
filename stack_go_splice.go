package tun

import (
	"github.com/metacubex/sing/common"
	"io"
	"net"
	"syscall"

	E "github.com/metacubex/sing/common/exceptions"
	N "github.com/metacubex/sing/common/network"
)

const (
	goSocketEventBatch = 64
	goSpliceTokenShift = 8
	goSpliceReadChunk  = 2 * goSlabSize
)

type SpliceSocket interface {
	syscall.Conn
	io.Closer
	Attach(closer io.Closer) (io.Closer, bool)
	Detach()
}

type SpliceOptions struct {
	ReadCounters  []N.CountFunc
	WriteCounters []N.CountFunc
	OnClose       func(error)
}

type goSpliceSlot struct {
	stream     *GoConn
	generation uint32
}

func (e *goEngine) allocateSpliceToken(stream *GoConn) uint32 {
	var index uint32
	if free := len(e.spliceFree); free > 0 {
		index = e.spliceFree[free-1]
		e.spliceFree = e.spliceFree[:free-1]
	} else {
		index = uint32(len(e.spliceSlots))
		e.spliceSlots = append(e.spliceSlots, goSpliceSlot{})
	}
	slot := &e.spliceSlots[index]
	slot.generation = (slot.generation + 1) & (1<<goSpliceTokenShift - 1)
	slot.stream = stream
	return index<<goSpliceTokenShift | slot.generation
}

func (e *goEngine) releaseSpliceToken(token uint32) {
	index := token >> goSpliceTokenShift
	slot := &e.spliceSlots[index]
	slot.stream = nil
	e.spliceFree = append(e.spliceFree, index)
}

func (e *goEngine) spliceSlot(token uint32) *goSpliceSlot {
	index := token >> goSpliceTokenShift
	if index >= uint32(len(e.spliceSlots)) {
		return nil
	}
	slot := &e.spliceSlots[index]
	if slot.generation != token&(1<<goSpliceTokenShift-1) {
		return nil
	}
	return slot
}

func (e *goEngine) dispatchSocketEvents(count int) {
	for index := 0; index < count; index++ {
		event := e.socketEvents[index]
		slot := e.spliceSlot(event.token)
		if slot == nil {
			continue
		}
		if slot.stream != nil {
			e.handleStreamEvent(slot.stream, event)
		}
	}
}

func goCount(counters []N.CountFunc, n int) {
	for _, counter := range counters {
		counter(int64(n))
	}
}

type goSpliceStream struct {
	conn           *GoConn
	owner          SpliceSocket
	original       io.Closer
	socket         goSocket
	token          uint32
	interest       uint8
	options        SpliceOptions
	dirtyNext      *GoConn
	dirty          bool
	blocked        bool
	readStalled    bool
	uploadClosed   bool
	downloadClosed bool
}

func (c *GoConn) Splice(owner SpliceSocket, options SpliceOptions) bool {
	if c.connState.Load() != goConnStateEstablished {
		return false
	}
	splice := &goSpliceStream{conn: c, owner: owner, options: options}
	original, attached := owner.Attach(splice)
	if !attached {
		return false
	}
	splice.original = original
	socket, err := goSpliceSocket(owner)
	if err != nil {
		owner.Detach()
		c.engine.stack.logger.Debug(E.Cause(err, "go: splice ", c.destination))
		return false
	}
	splice.socket = socket
	if !c.splicePending.CompareAndSwap(nil, splice) {
		socket.close()
		owner.Detach()
		return false
	}
	c.engine.postMessage(&c.spliceMessage)
	return true
}

func (s *goSpliceStream) Close() error {
	s.conn.requestAbort(net.ErrClosed)
	return nil
}

func (e *goEngine) handleSpliceEngage(conn *GoConn) {
	splice := conn.splicePending.Load()
	if splice == nil {
		return
	}
	if conn.splice != nil {
		conn.splicePending.Store(nil)
		e.spliceRelease(splice, net.ErrClosed)
		return
	}
	if conn.connState.Load() >= goConnStateAborted {
		conn.splicePending.Store(nil)
		e.spliceRelease(splice, conn.closeError())
		return
	}
	splice.token = e.allocateSpliceToken(conn)
	var err error
	if goSpliceDuplicatesSocket {
		err = splice.original.Close()
	}
	if err == nil {
		err = e.platformIO.registerSocket(&splice.socket, splice.token, goInterestRead)
	}
	if err != nil {
		conn.splicePending.Store(nil)
		e.releaseSpliceToken(splice.token)
		e.spliceRelease(splice, err)
		e.spliceAbort(conn, err)
		return
	}
	splice.interest = goInterestRead
	conn.splice = splice
	conn.spliced.Store(true)
	conn.splicePending.Store(nil)
	e.spliceFlushUpload(conn)
}

func (e *goEngine) spliceRelease(splice *goSpliceStream, err error) {
	splice.socket.close()
	splice.owner.Detach()
	splice.owner.Close()
	if splice.options.OnClose != nil {
		splice.options.OnClose(err)
	}
}

func (e *goEngine) spliceDetach(conn *GoConn, err error) {
	pending := conn.splicePending.Swap(nil)
	if pending != nil {
		e.spliceRelease(pending, err)
	}
	splice := conn.splice
	if splice == nil {
		return
	}
	if splice.dirty {
		e.spliceUnlinkDirty(conn)
	}
	conn.splice = nil
	conn.spliced.Store(false)
	e.platformIO.unregisterSocket(&splice.socket)
	e.releaseSpliceToken(splice.token)
	e.spliceRelease(splice, err)
}

func (e *goEngine) spliceUnlinkDirty(conn *GoConn) {
	splice := conn.splice
	splice.dirty = false
	if e.spliceDirtyList == conn {
		e.spliceDirtyList = splice.dirtyNext
		splice.dirtyNext = nil
		return
	}
	for previous := e.spliceDirtyList; previous != nil; previous = previous.splice.dirtyNext {
		if previous.splice.dirtyNext == conn {
			previous.splice.dirtyNext = splice.dirtyNext
			splice.dirtyNext = nil
			return
		}
	}
}

func (e *goEngine) spliceAbort(conn *GoConn, err error) {
	if conn.connState.Load() >= goConnStateDead {
		conn.storeError(err)
		conn.receiveDrainable.Store(false)
		e.spliceDetach(conn, err)
		return
	}
	e.sendReset(conn)
	e.detachConn(conn, err, goDeathAbortLinger)
}

func (e *goEngine) spliceSetInterest(conn *GoConn, interest uint8) {
	splice := conn.splice
	if splice.interest == interest {
		return
	}
	splice.interest = interest
	err := e.platformIO.updateSocket(&splice.socket, interest)
	if err != nil {
		e.spliceAbort(conn, err)
	}
}

func (e *goEngine) handleStreamEvent(conn *GoConn, event goSocketEvent) {
	if event.writable && conn.splice != nil {
		conn.splice.blocked = false
		e.spliceFlushUpload(conn)
	}
	if event.readable && conn.splice != nil {
		e.spliceReadPeer(conn)
	}
}

func (e *goEngine) spliceDeliver(conn *GoConn, data []byte) {
	conn.receiveChain.reserve(conn.receiveNext, len(data))
	conn.receiveChain.writeAt(conn.receiveNext, data)
	conn.receiveNext += uint64(len(data))
	conn.receiveNextAck.Store(conn.receiveNext)
	conn.receiveAvailable.Store(conn.receiveNext)
	conn.publishReceiveWindow()
	e.spliceMarkDirty(conn)
}

func (e *goEngine) spliceMarkDirty(conn *GoConn) {
	splice := conn.splice
	if splice.dirty {
		return
	}
	splice.dirty = true
	splice.dirtyNext = e.spliceDirtyList
	e.spliceDirtyList = conn
}

func (e *goEngine) flushSpliceDirty() {
	for conn := e.spliceDirtyList; conn != nil; {
		splice := conn.splice
		next := splice.dirtyNext
		splice.dirtyNext = nil
		splice.dirty = false
		e.spliceFlushUpload(conn)
		conn = next
	}
	e.spliceDirtyList = nil
}

func (e *goEngine) spliceFlushUpload(conn *GoConn) {
	splice := conn.splice
	for !splice.blocked {
		consumed := conn.consumedTail.Load()
		available := conn.receiveAvailable.Load()
		if consumed >= available {
			break
		}
		e.spliceSegments = conn.receiveChain.appendRuns(e.spliceSegments[:0], consumed, int(available-consumed))
		e.spliceIovecs = goIovecsFromSegments(e.spliceIovecs, e.spliceSegments)
		n, errno := splice.socket.writeVector(e.spliceIovecs)
		switch {
		case errno == 0:
			consumed = conn.consumedTail.Add(uint64(n))
			goCount(splice.options.ReadCounters, n)
			if consumed < available {
				splice.blocked = true
			}
			if conn.windowUpdateDue(consumed) {
				e.handleWindowUpdate(conn)
			}
		case goSocketWouldBlock(errno):
			splice.blocked = true
		default:
			e.spliceAbort(conn, E.Cause(errno, "go: write peer"))
			return
		}
	}
	consumed := conn.consumedTail.Load()
	conn.receiveChain.releaseBelow(consumed)
	if consumed == conn.receiveAvailable.Load() && (conn.oooRanges == nil || conn.oooRanges.count == 0) {
		conn.receiveChain.releaseDrained(consumed)
	}
	interest := splice.interest &^ goInterestWrite
	if splice.blocked {
		interest |= goInterestWrite
	}
	e.spliceSetInterest(conn, interest)
	if conn.splice != nil {
		e.spliceCheckUpload(conn)
	}
}

func (e *goEngine) spliceCheckUpload(conn *GoConn) {
	splice := conn.splice
	if splice.uploadClosed || !conn.finReceived || conn.receiveAvailable.Load() > conn.consumedTail.Load() {
		return
	}
	splice.socket.shutdownWrite()
	splice.uploadClosed = true
	e.spliceMaybeFinish(conn)
}

func (e *goEngine) spliceAfterInput(conn *GoConn) {
	splice := conn.splice
	if splice == nil {
		return
	}
	if conn.receiveAvailable.Load() > conn.consumedTail.Load() || (conn.finReceived && !splice.uploadClosed) {
		e.spliceMarkDirty(conn)
		return
	}
	e.spliceMaybeFinish(conn)
}

func (e *goEngine) spliceReadPeer(conn *GoConn) {
	// Empty speculative reads must not keep the partial tail slab while the
	// socket is waiting. Unacknowledged and out-of-order data remain retained.
	defer conn.releaseDrainedSlabs()
	splice := conn.splice
	for !splice.downloadClosed {
		budget := conn.writeBudget(0)
		if budget <= 0 {
			splice.readStalled = true
			e.spliceSetInterest(conn, splice.interest&^goInterestRead)
			return
		}
		budget = common.Min(budget, goSpliceReadChunk)
		buffered := conn.bufferedTail.Load()
		conn.transmitStore.reserve(buffered, budget)
		e.spliceSegments = conn.transmitStore.chain.appendRuns(e.spliceSegments[:0], buffered, budget)
		e.spliceIovecs = goIovecsFromSegments(e.spliceIovecs, e.spliceSegments)
		n, errno := splice.socket.readVector(e.spliceIovecs)
		if errno != 0 || n < 0 {
			n = 0
		}
		if n < budget {
			conn.transmitStore.shrinkReserve(buffered + uint64(n))
		}
		switch {
		case errno == 0 && n == 0:
			splice.downloadClosed = true
			e.spliceSetInterest(conn, splice.interest&^goInterestRead)
			if conn.splice == nil {
				return
			}
			conn.finPending = true
		case errno == 0:
			conn.bufferedTail.Store(buffered + uint64(n))
			goCount(splice.options.WriteCounters, n)
			if !e.spliceTransmit(conn) {
				return
			}
		case goSocketWouldBlock(errno):
			e.spliceMaybeFinish(conn)
			return
		default:
			e.spliceAbort(conn, E.Cause(errno, "go: read peer"))
			return
		}
	}
	e.maybeSendFin(conn)
	e.spliceMaybeFinish(conn)
}

func (e *goEngine) spliceTransmit(conn *GoConn) bool {
	if conn.blockedValid || !conn.transmitOwner.CompareAndSwap(0, 1) {
		return true
	}
	_, blocked := conn.transmitLoop(false, 0)
	conn.transmitOwner.Store(0)
	if conn.connState.Load() >= goConnStateAborted {
		return false
	}
	if blocked {
		e.handleTransmitBlocked(conn)
	}
	return true
}

func (e *goEngine) spliceResume(conn *GoConn) {
	if !e.spliceTransmit(conn) {
		return
	}
	splice := conn.splice
	if splice == nil || !splice.readStalled || splice.downloadClosed || conn.writeBudget(0) <= 0 {
		return
	}
	splice.readStalled = false
	e.spliceSetInterest(conn, splice.interest|goInterestRead)
}

func (e *goEngine) spliceRetryBlocked(conn *GoConn) {
	segment := conn.blockedSegment
	end := segment.offset + uint64(segment.length)
	err := conn.transmitFrame(&segment)
	switch err {
	case nil:
	case errGoTransmitBlocked:
		conn.amendDescriptors(segment.offset, segment.length, goDescriptorNoSample)
		e.handleTransmitBlocked(conn)
		return
	case errGoFrameDropped:
		conn.amendDescriptors(segment.offset, segment.length, goDescriptorDropped)
		conn.blockedValid = false
		conn.blockedFrame = nil
		conn.transmittedTail.Store(end)
		e.handleDroppedFrames(conn)
		return
	default:
		e.spliceAbort(conn, E.Cause(err, "go: write tun"))
		return
	}
	conn.blockedValid = false
	conn.blockedFrame = nil
	conn.transmittedTail.Store(end)
	e.spliceResume(conn)
	if conn.splice != nil && conn.splice.downloadClosed {
		e.maybeSendFin(conn)
		e.spliceMaybeFinish(conn)
	}
}

func (e *goEngine) spliceMaybeFinish(conn *GoConn) {
	splice := conn.splice
	if splice == nil || !splice.uploadClosed || !splice.downloadClosed || !conn.finSent {
		return
	}
	e.spliceDetach(conn, nil)
}

func (e *goEngine) releasePending(message *goMessage) {
	switch message.kind {
	case goMessageConnSplice:
		pending := message.conn.splicePending.Swap(nil)
		if pending != nil {
			e.spliceRelease(pending, net.ErrClosed)
		}
	case goMessageInject:
		e.releaseInjected()
	}
}
