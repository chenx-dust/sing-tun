package tun

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"
)

type MemoryPressure uint8

const (
	MemoryPressureNone MemoryPressure = iota
	MemoryPressureWarning
	MemoryPressureCritical
)

// Go is a user-space TCP/IP stack ported from upstream sing-tun. It reads the
// TUN device with its own event loop (one per queue) and terminates TCP itself;
// UDP datagrams and ICMP echo are handed to the Handler like the other stacks.
type Go struct {
	ctx                  context.Context
	tun                  Tun
	mtu                  int
	handler              Handler
	logger               logger.Logger
	inet4Address         netip.Addr
	inet6Address         netip.Addr
	broadcastAddr        netip.Addr
	inet4LoopbackAddress []netip.Addr
	inet6LoopbackAddress []netip.Addr
	icmpMapping          *DirectRouteMapping
	icmpSlots            chan struct{}
	memoryPressure       func() MemoryPressure
	udpIdentification    atomic.Uint32
	directory            goFlowDirectory
	access               sync.Mutex
	engines              []*goEngine
	closed               atomic.Bool
}

func NewGo(options StackOptions) (Stack, error) {
	if options.Context == nil {
		options.Context = context.Background()
	}
	icmpTimeout := options.ICMPTimeout
	if icmpTimeout == 0 {
		icmpTimeout = time.Minute
	}
	stack := &Go{
		ctx:                  options.Context,
		tun:                  options.Tun,
		mtu:                  int(options.TunOptions.MTU),
		handler:              options.Handler,
		logger:               options.Logger,
		broadcastAddr:        BroadcastAddr(options.TunOptions.Inet4Address),
		inet4LoopbackAddress: options.TunOptions.Inet4LoopbackAddress,
		inet6LoopbackAddress: options.TunOptions.Inet6LoopbackAddress,
		icmpMapping:          NewDirectRouteMapping(icmpTimeout),
		icmpSlots:            make(chan struct{}, 16),
		memoryPressure:       options.MemoryPressure,
	}
	if len(options.TunOptions.Inet4Address) > 0 {
		stack.inet4Address = options.TunOptions.Inet4Address[0].Addr()
	}
	if len(options.TunOptions.Inet6Address) > 0 {
		stack.inet6Address = options.TunOptions.Inet6Address[0].Addr()
	}
	if stack.mtu == 0 {
		stack.mtu = 9000
	}
	return stack, nil
}

func (s *Go) Start() error {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed.Load() {
		return E.New("stack is closed")
	}
	queues, err := newGoPlatformQueues(s)
	if err != nil {
		return err
	}
	for index, queue := range queues {
		err = queue.start()
		if err == nil {
			continue
		}
		if index > 0 && errors.Is(err, errGoQueueUnavailable) {
			queues = queues[:index]
			break
		}
		return E.Errors(err, goCloseQueues(queues[:index]))
	}
	if len(queues) > 1 {
		s.directory.flows = make(map[flowKey]*GoConn)
	}
	s.engines = make([]*goEngine, len(queues))
	for index, queue := range queues {
		s.engines[index] = newGoEngine(s, queue, len(queues))
	}
	for _, engine := range s.engines {
		go engine.run()
	}
	return nil
}

func goCloseQueues(queues []goPlatformIO) error {
	var err error
	for _, queue := range queues {
		err = E.Errors(err, queue.close())
	}
	return err
}

// goFlowDirectory maps TCP flows to the engine that owns them when the TUN is
// multi-queue, so a segment read by another queue can be handed over.
type goFlowDirectory struct {
	access sync.RWMutex
	flows  map[flowKey]*GoConn
}

func (d *goFlowDirectory) insert(key flowKey, conn *GoConn) {
	if d.flows == nil {
		return
	}
	d.access.Lock()
	d.flows[key] = conn
	d.access.Unlock()
}

func (d *goFlowDirectory) remove(key flowKey, conn *GoConn) {
	if d.flows == nil {
		return
	}
	d.access.Lock()
	if d.flows[key] == conn {
		delete(d.flows, key)
	}
	d.access.Unlock()
}

func (d *goFlowDirectory) lookup(key flowKey) *GoConn {
	if d.flows == nil {
		return nil
	}
	d.access.RLock()
	conn := d.flows[key]
	d.access.RUnlock()
	return conn
}

// ResetNetwork reclaims idle buffers after a network change. It is not part of
// the Stack interface in this fork.
func (s *Go) ResetNetwork() {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed.Load() {
		return
	}
	for _, engine := range s.engines {
		engine.postMessage(&engine.resetMessage)
	}
}

func (s *Go) Close() error {
	s.access.Lock()
	if !s.closed.CompareAndSwap(false, true) {
		s.access.Unlock()
		return nil
	}
	for _, engine := range s.engines {
		engine.postMessage(&engine.closeMessage)
	}
	s.access.Unlock()
	for _, engine := range s.engines {
		<-engine.exitSignal
	}
	var err error
	for _, engine := range s.engines {
		err = E.Errors(err, engine.platformIO.close())
	}
	return err
}
