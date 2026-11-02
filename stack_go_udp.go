package tun

import (
	"net/netip"
	"os"

	"github.com/metacubex/sing-tun/internal/gtcpip/checksum"
	"github.com/metacubex/sing-tun/internal/gtcpip/header"
	"github.com/metacubex/sing/common/buf"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

const (
	goPacketBatchSize   = 32
	goUDPGSOType        = 5
	goUDPChecksumOffset = 6
)

func (e *goEngine) processUDPSegments(frame *goFrame) {
	meta := frame.meta
	packet := frame.buffer.Bytes()
	parsed, parsedOK := parseForwardPacket(packet)
	headerLength := int(meta.checksumStart) + header.UDPMinimumSize
	if !parsedOK || parsed.protocol != uint8(header.UDPProtocolNumber) || parsed.fragment || meta.gsoSize == 0 || headerLength > len(packet) {
		return
	}
	count := (len(packet) - headerLength + int(meta.gsoSize) - 1) / int(meta.gsoSize)
	if count == 0 {
		return
	}
	options := *e.packetReadOptions.Load()
	buffers := newGoReadBuffers(headerLength+int(meta.gsoSize), count, options)
	defer buf.ReleaseMulti(buffers)
	segments := make([][]byte, count)
	sizes := make([]int, count)
	for index, buffer := range buffers {
		segments[index] = buffer.FreeBytes()
	}
	count, err := GSOSplit(packet, GSOOptions{
		GSOType: GSOUDPL4, HdrLen: uint16(headerLength), GSOSize: meta.gsoSize,
		CsumStart: meta.checksumStart, CsumOffset: meta.checksumOffset, NeedsCsum: meta.needsChecksum,
	}, segments, sizes, 0)
	if err != nil {
		e.stack.logger.Trace(E.Cause(err, "go: split UDP segments"))
		return
	}
	for index := 0; index < count; index++ {
		buffer := buffers[index]
		buffer.Truncate(sizes[index])
		options.PostReturn(buffer)
		e.processFrame(&goFrame{buffer: buffer})
	}
}

// demuxUDP hands every datagram to the handler, which owns the UDP NAT in this
// fork; replies come back through a GoPacketConn writing straight to the TUN.
func (e *goEngine) demuxUDP(parsed *forwardPacket) {
	if len(parsed.transport) < header.UDPMinimumSize {
		return
	}
	payload := header.UDP(parsed.transport).Payload()
	buffer := buf.NewSize(len(payload))
	_, _ = buffer.Write(payload)
	source := parsed.source
	ipVersion := parsed.ipVersion
	e.stack.handler.NewPacket(
		e.stack.ctx,
		source,
		buffer,
		M.Metadata{
			Source:      M.SocksaddrFromNetIP(source),
			Destination: M.SocksaddrFromNetIP(parsed.destination),
		},
		func(N.PacketConn) N.PacketWriter {
			return newGoPacketConn(e, ipVersion, source)
		},
	)
	e.wokeHandlerThisBurst = true
}

type GoPacketConn struct {
	stack           *Go
	platformIO      goPlatformIO
	mtu             int
	ipVersion       uint8
	templateLength  int
	checksumOffload bool
	template        [header.IPv6MinimumSize + header.UDPMinimumSize]byte
}

func newGoPacketConn(engine *goEngine, ipVersion uint8, client netip.AddrPort) *GoPacketConn {
	writer := &GoPacketConn{
		stack:           engine.stack,
		platformIO:      engine.platformIO,
		mtu:             engine.stack.mtu,
		checksumOffload: engine.platformIO.transmitChecksumOffload(),
	}
	writer.buildTemplate(ipVersion, client)
	return writer
}

func (w *GoPacketConn) buildTemplate(ipVersion uint8, client netip.AddrPort) {
	w.ipVersion = ipVersion
	clientAddr := client.Addr()
	if ipVersion == 4 {
		w.templateLength = header.IPv4MinimumSize + header.UDPMinimumSize
		ipHdr := header.IPv4(w.template[:w.templateLength])
		ipHdr.Encode(&header.IPv4Fields{
			TotalLength: uint16(w.templateLength),
			TTL:         synthesizedTTL,
			Protocol:    uint8(header.UDPProtocolNumber),
			SrcAddr:     clientAddr,
			DstAddr:     clientAddr,
		})
		header.UDP(ipHdr[header.IPv4MinimumSize:]).Encode(&header.UDPFields{
			DstPort: client.Port(),
		})
	} else {
		w.templateLength = header.IPv6MinimumSize + header.UDPMinimumSize
		ipHdr := header.IPv6(w.template[:w.templateLength])
		ipHdr.Encode(&header.IPv6Fields{
			PayloadLength:     header.UDPMinimumSize,
			TransportProtocol: header.UDPProtocolNumber,
			HopLimit:          synthesizedTTL,
			SrcAddr:           clientAddr,
			DstAddr:           clientAddr,
		})
		header.UDP(ipHdr[header.IPv6MinimumSize:]).Encode(&header.UDPFields{
			DstPort: client.Port(),
		})
	}
}

func (w *GoPacketConn) preparePacketHeader(packet []byte, payload []byte, destination M.Socksaddr, checksumOffload bool) (ForwardFrameMeta, error) {
	maximumPayload := 65535 - header.UDPMinimumSize
	if w.ipVersion == 4 {
		maximumPayload -= header.IPv4MinimumSize
	}
	if len(payload) > maximumPayload {
		return ForwardFrameMeta{}, errGoFrameDropped
	}
	if !destination.IsIP() || w.ipVersion == 4 && !destination.IsIPv4() {
		return ForwardFrameMeta{}, E.New("go: invalid packet destination")
	}
	if w.ipVersion == 6 && destination.IsIPv4() {
		destination = M.SocksaddrFrom(netip.AddrFrom16(destination.Addr.As16()), destination.Port)
	}
	var meta ForwardFrameMeta
	copy(packet, w.template[:w.templateLength])
	udpLength := uint16(header.UDPMinimumSize + len(payload))
	var sourceAddress, destinationAddress []byte
	if w.ipVersion == 4 {
		ipHdr := header.IPv4(packet[:header.IPv4MinimumSize])
		ipHdr.SetTotalLength(uint16(w.templateLength + len(payload)))
		ipHdr.SetSourceAddr(destination.Addr)
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
		sourceAddress = ipHdr.SourceAddressSlice()
		destinationAddress = ipHdr.DestinationAddressSlice()
	} else {
		ipHdr := header.IPv6(packet[:header.IPv6MinimumSize])
		ipHdr.SetPayloadLength(udpLength)
		ipHdr.SetSourceAddr(destination.Addr)
		sourceAddress = ipHdr.SourceAddressSlice()
		destinationAddress = ipHdr.DestinationAddressSlice()
	}
	udpHdr := header.UDP(packet[w.templateLength-header.UDPMinimumSize : w.templateLength])
	udpHdr.SetSourcePort(destination.Port)
	udpHdr.SetLength(udpLength)
	pseudoSum := header.PseudoHeaderChecksum(header.UDPProtocolNumber, sourceAddress, destinationAddress, udpLength)
	if checksumOffload {
		udpHdr.SetChecksum(pseudoSum)
		meta.needsChecksum = true
		meta.checksumStart = uint16(w.templateLength - header.UDPMinimumSize)
		meta.checksumOffset = goUDPChecksumOffset
	} else {
		sum := ^checksum.Checksum(payload, udpHdr.CalculateChecksum(pseudoSum))
		if sum == 0 {
			sum = 0xffff
		}
		udpHdr.SetChecksum(sum)
	}
	return meta, nil
}

func (w *GoPacketConn) FrontHeadroom() int {
	return w.platformIO.transmitPrefix() + w.templateLength
}

func (w *GoPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	if !destination.IsIP() {
		return E.Cause(os.ErrInvalid, "invalid destination")
	}
	if buffer.Start() < w.templateLength {
		// The handler ignored FrontHeadroom; copy into a buffer that has room for the headers.
		newBuffer := buf.NewSize(w.templateLength + buffer.Len())
		defer newBuffer.Release()
		newBuffer.Resize(w.templateLength, 0)
		_, _ = newBuffer.Write(buffer.Bytes())
		buffer = newBuffer
	}
	return w.transmit(buffer, destination)
}

func (w *GoPacketConn) transmit(buffer *buf.Buffer, destination M.Socksaddr) error {
	payload := buffer.Bytes()
	fragmented := w.templateLength+len(payload) > w.mtu
	meta, err := w.preparePacketHeader(buffer.ExtendHeader(w.templateLength), payload, destination, w.checksumOffload && !fragmented)
	if err != nil {
		if w.ipVersion == 4 && destination.IsIPv6() {
			return E.New("send IPv6 packet to IPv4 connection")
		}
		return goIgnoreDropped(err)
	}
	packet := buffer.Bytes()
	if !fragmented {
		return goIgnoreDropped(w.platformIO.writeFrame([][]byte{packet}, meta))
	}
	var (
		fragments      [][]byte
		fragmentsBuilt bool
	)
	if w.ipVersion == 4 {
		ipHdr := header.IPv4(packet)
		ipHdr.SetID(uint16(w.stack.udpIdentification.Add(1)))
		ipHdr.SetChecksum(0)
		ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
		fragments, fragmentsBuilt = fragmentIPv4Packet(ipHdr, uint32(w.mtu))
	} else {
		fragments, fragmentsBuilt = fragmentIPv6Packet(header.IPv6(packet), uint32(w.mtu), w.stack.udpIdentification.Add(1))
	}
	if !fragmentsBuilt {
		return nil
	}
	var writeErr error
	for _, fragment := range fragments {
		writeErr = E.Errors(writeErr, goIgnoreDropped(w.platformIO.writeFrame([][]byte{fragment}, ForwardFrameMeta{})))
	}
	return writeErr
}

var (
	_ N.PacketWriter  = (*GoPacketConn)(nil)
	_ N.FrontHeadroom = (*GoPacketConn)(nil)
)
