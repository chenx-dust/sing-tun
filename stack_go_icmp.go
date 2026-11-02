package tun

import (
	"errors"
	"time"

	"github.com/metacubex/sing-tun/internal/gtcpip/header"
	"github.com/metacubex/sing/common/buf"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// demuxICMP answers echo requests for the TUN's own addresses and asks the
// handler, through PrepareConnection, what to do with the rest, matching the
// system and mipstack stacks.
func (e *goEngine) demuxICMP(packet []byte, parsed *forwardPacket) {
	switch parsed.protocol {
	case uint8(header.ICMPv4ProtocolNumber):
		if len(parsed.transport) < header.ICMPv4MinimumSize || header.ICMPv4Type(parsed.icmpType) != header.ICMPv4Echo {
			return
		}
	case uint8(header.ICMPv6ProtocolNumber):
		if len(parsed.transport) < header.ICMPv6MinimumSize || header.ICMPv6Type(parsed.icmpType) != header.ICMPv6EchoRequest {
			return
		}
	default:
		return
	}
	destination := parsed.destination.Addr()
	if destination == e.stack.inet4Address || destination == e.stack.inet6Address {
		goAnswerEcho(e.platformIO, packet, e.stack.logger)
		return
	}
	select {
	case e.stack.icmpSlots <- struct{}{}:
	default:
		return
	}
	request := make([]byte, len(packet))
	copy(request, packet)
	session := DirectRouteSession{Source: parsed.source.Addr(), Destination: destination}
	go func() {
		defer func() { <-e.stack.icmpSlots }()
		e.stack.forwardICMP(e.platformIO, request, session)
	}()
}

func (s *Go) forwardICMP(platformIO goPlatformIO, packet []byte, session DirectRouteSession) {
	action, err := s.icmpMapping.Lookup(session, func(timeout time.Duration) (DirectRouteDestination, error) {
		destination, err := s.handler.PrepareConnection(
			N.NetworkICMP,
			M.SocksaddrFrom(session.Source, 0),
			M.SocksaddrFrom(session.Destination, 0),
			&goICMPWriter{platformIO: platformIO},
			timeout,
		)
		if err != nil {
			if destination != nil {
				_ = destination.Close()
			}
			return nil, err
		}
		return destination, nil
	})
	if errors.Is(err, ErrReset) {
		reply, ok := BuildUnreachable(packet, session.Destination, 0)
		if ok {
			err = platformIO.writeFrame([][]byte{reply}, ForwardFrameMeta{})
			if err != nil {
				s.logger.Trace(E.Cause(err, "go: write unreachable"))
			}
		}
		return
	} else if errors.Is(err, ErrDrop) {
		return
	}
	if action != nil {
		buffer := buf.NewSize(len(packet))
		_, _ = buffer.Write(packet)
		err = action.WritePacket(buffer)
		if err != nil {
			s.logger.Trace(E.Cause(err, "go: forward ICMP"))
		}
		return
	}
	goAnswerEcho(platformIO, packet, s.logger)
}

func goAnswerEcho(platformIO goPlatformIO, packet []byte, stackLogger logger.Logger) {
	parsed, ok := parseForwardPacket(packet)
	if !ok {
		return
	}
	switch parsed.protocol {
	case uint8(header.ICMPv4ProtocolNumber):
		if !rewriteEchoReplyIPv4(header.IPv4(parsed.network), header.ICMPv4(parsed.transport)) {
			return
		}
	case uint8(header.ICMPv6ProtocolNumber):
		if !rewriteEchoReplyIPv6(header.IPv6(parsed.network), header.ICMPv6(parsed.transport)) {
			return
		}
	default:
		return
	}
	err := platformIO.writeFrame([][]byte{packet}, ForwardFrameMeta{})
	if err != nil {
		stackLogger.Trace(E.Cause(err, "go: write echo reply"))
	}
}

type goICMPWriter struct {
	platformIO goPlatformIO
}

func (w *goICMPWriter) WritePacket(packet []byte) error {
	return goIgnoreDropped(w.platformIO.writeFrame([][]byte{packet}, ForwardFrameMeta{}))
}
