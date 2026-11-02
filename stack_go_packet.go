package tun

import (
	"encoding/binary"
	"net/netip"
	"time"

	"github.com/metacubex/sing-tun/internal/gtcpip/checksum"
	"github.com/metacubex/sing-tun/internal/gtcpip/header"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/buf"
	N "github.com/metacubex/sing/common/network"
)

// Packet helpers shared by the go stack. Upstream keeps these in its flow
// dispatcher, which this fork does not carry.

const (
	tcpEstablishedTimeout = 2*time.Hour + 4*time.Minute
	synthesizedTTL        = 64
)

type ForwardFrameMeta struct {
	needsChecksum  bool
	checksumStart  uint16
	checksumOffset uint16
	gsoType        uint8
	gsoSize        uint16
}

type flowKey struct {
	protocol    uint8
	source      netip.AddrPort
	destination netip.AddrPort
}

type forwardPacket struct {
	ipVersion   uint8
	protocol    uint8
	network     []byte
	transport   []byte
	source      netip.AddrPort
	destination netip.AddrPort
	tcpFlags    header.TCPFlags
	icmpType    uint8
	fragment    bool
	hasFlow     bool
}

func (p *forwardPacket) flowKey() flowKey {
	return flowKey{protocol: p.protocol, source: p.source, destination: p.destination}
}

func parseForwardPacket(packet []byte) (forwardPacket, bool) {
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ipHdr := header.IPv4(packet)
		if !ipHdr.IsValid(len(packet)) {
			return forwardPacket{}, false
		}
		parsed := forwardPacket{
			ipVersion:   4,
			protocol:    uint8(ipHdr.TransportProtocol()),
			network:     packet,
			source:      netip.AddrPortFrom(ipHdr.SourceAddr(), 0),
			destination: netip.AddrPortFrom(ipHdr.DestinationAddr(), 0),
		}
		if ipHdr.More() || ipHdr.FragmentOffset() != 0 {
			parsed.fragment = true
			return parsed, true
		}
		parsed.parseTransport(ipHdr.Payload())
		return parsed, true
	case header.IPv6Version:
		ipHdr := header.IPv6(packet)
		if !ipHdr.IsValid(len(packet)) {
			return forwardPacket{}, false
		}
		protocol := uint8(ipHdr.TransportProtocol())
		parsed := forwardPacket{
			ipVersion:   6,
			protocol:    protocol,
			network:     packet,
			source:      netip.AddrPortFrom(ipHdr.SourceAddr(), 0),
			destination: netip.AddrPortFrom(ipHdr.DestinationAddr(), 0),
		}
		switch header.IPv6ExtensionHeaderIdentifier(protocol) {
		case header.IPv6HopByHopOptionsExtHdrIdentifier, header.IPv6RoutingExtHdrIdentifier, header.IPv6DestinationOptionsExtHdrIdentifier:
			return forwardPacket{}, false
		case header.IPv6FragmentExtHdrIdentifier:
			parsed.fragment = true
			return parsed, true
		}
		parsed.parseTransport(ipHdr.Payload())
		return parsed, true
	default:
		return forwardPacket{}, false
	}
}

func (p *forwardPacket) parseTransport(payload []byte) {
	p.transport = payload
	switch p.protocol {
	case uint8(header.TCPProtocolNumber):
		if len(payload) < header.TCPMinimumSize {
			return
		}
		tcpHdr := header.TCP(payload)
		tcpHeaderLength := int(tcpHdr.DataOffset())
		if tcpHeaderLength < header.TCPMinimumSize || tcpHeaderLength > len(payload) {
			return
		}
		p.source = netip.AddrPortFrom(p.source.Addr(), tcpHdr.SourcePort())
		p.destination = netip.AddrPortFrom(p.destination.Addr(), tcpHdr.DestinationPort())
		p.tcpFlags = tcpHdr.Flags()
		p.hasFlow = true
	case uint8(header.UDPProtocolNumber):
		if len(payload) < header.UDPMinimumSize {
			return
		}
		udpHdr := header.UDP(payload)
		p.source = netip.AddrPortFrom(p.source.Addr(), udpHdr.SourcePort())
		p.destination = netip.AddrPortFrom(p.destination.Addr(), udpHdr.DestinationPort())
		p.hasFlow = true
	case uint8(header.ICMPv4ProtocolNumber):
		if len(payload) < header.ICMPv4MinimumSize {
			return
		}
		icmpHdr := header.ICMPv4(payload)
		p.icmpType = uint8(icmpHdr.Type())
		switch icmpHdr.Type() {
		case header.ICMPv4Echo, header.ICMPv4EchoReply:
			identifier := icmpHdr.Ident()
			p.source = netip.AddrPortFrom(p.source.Addr(), identifier)
			p.destination = netip.AddrPortFrom(p.destination.Addr(), identifier)
			p.hasFlow = true
		}
	case uint8(header.ICMPv6ProtocolNumber):
		if len(payload) < header.ICMPv6MinimumSize {
			return
		}
		icmpHdr := header.ICMPv6(payload)
		p.icmpType = uint8(icmpHdr.Type())
		switch icmpHdr.Type() {
		case header.ICMPv6EchoRequest, header.ICMPv6EchoReply:
			identifier := icmpHdr.Ident()
			p.source = netip.AddrPortFrom(p.source.Addr(), identifier)
			p.destination = netip.AddrPortFrom(p.destination.Addr(), identifier)
			p.hasFlow = true
		}
	}
}

func rewriteEchoReplyIPv4(ipHdr header.IPv4, icmpHdr header.ICMPv4) bool {
	if icmpHdr.Type() != header.ICMPv4Echo || icmpHdr.Code() != 0 {
		return false
	}
	icmpHdr.SetType(header.ICMPv4EchoReply)
	sourceAddress := ipHdr.SourceAddr()
	ipHdr.SetSourceAddr(ipHdr.DestinationAddr())
	ipHdr.SetDestinationAddr(sourceAddress)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr, 0))
	ipHdr.SetChecksum(^ipHdr.CalculateChecksum())
	return true
}

func rewriteEchoReplyIPv6(ipHdr header.IPv6, icmpHdr header.ICMPv6) bool {
	if icmpHdr.Type() != header.ICMPv6EchoRequest || icmpHdr.Code() != 0 {
		return false
	}
	icmpHdr.SetType(header.ICMPv6EchoReply)
	sourceAddress := ipHdr.SourceAddr()
	ipHdr.SetSourceAddr(ipHdr.DestinationAddr())
	ipHdr.SetDestinationAddr(sourceAddress)
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHdr,
		Src:    ipHdr.SourceAddressSlice(),
		Dst:    ipHdr.DestinationAddressSlice(),
	}))
	return true
}

func fragmentIPv4Packet(packet header.IPv4, effectiveMTU uint32) ([][]byte, bool) {
	headerLength := int(packet.HeaderLength())
	if headerLength < header.IPv4MinimumSize || headerLength >= len(packet) {
		return nil, false
	}
	payload := packet[headerLength:]
	maxFragmentPayload := (int(effectiveMTU) - headerLength) &^ 7
	if maxFragmentPayload <= 0 {
		return nil, false
	}
	baseOffset := packet.FragmentOffset()
	originalMore := packet.Flags()&header.IPv4FlagMoreFragments != 0
	baseFlags := packet.Flags() &^ header.IPv4FlagMoreFragments
	fragments := make([][]byte, 0, (len(payload)+maxFragmentPayload-1)/maxFragmentPayload)
	for start := 0; start < len(payload); start += maxFragmentPayload {
		end := common.Min(start+maxFragmentPayload, len(payload))
		fragment := header.IPv4(make([]byte, headerLength+end-start))
		copy(fragment, packet[:headerLength])
		copy(fragment[headerLength:], payload[start:end])
		flags := baseFlags
		if originalMore || end < len(payload) {
			flags |= header.IPv4FlagMoreFragments
		}
		fragment.SetFlagsFragmentOffset(flags, baseOffset+uint16(start))
		fragment.SetTotalLength(uint16(len(fragment)))
		fragment.SetChecksum(0)
		fragment.SetChecksum(^fragment.CalculateChecksum())
		fragments = append(fragments, fragment)
	}
	return fragments, true
}

func fragmentIPv6Packet(packet header.IPv6, effectiveMTU uint32, ident uint32) ([][]byte, bool) {
	if len(packet) < header.IPv6MinimumSize {
		return nil, false
	}
	payload := packet.Payload()
	maxFragmentPayload := (int(effectiveMTU) - header.IPv6MinimumSize - header.IPv6FragmentHeaderSize) &^ 7
	if maxFragmentPayload <= 0 {
		return nil, false
	}
	transportProtocol := packet.NextHeader()
	fragments := make([][]byte, 0, (len(payload)+maxFragmentPayload-1)/maxFragmentPayload)
	for start := 0; start < len(payload); start += maxFragmentPayload {
		end := common.Min(start+maxFragmentPayload, len(payload))
		fragment := header.IPv6(make([]byte, header.IPv6MinimumSize+header.IPv6FragmentHeaderSize+end-start))
		copy(fragment, packet[:header.IPv6MinimumSize])
		fragment.SetNextHeader(header.IPv6FragmentHeader)
		fragment.SetPayloadLength(uint16(header.IPv6FragmentHeaderSize + end - start))
		encodeIPv6FragmentHeader(fragment[header.IPv6MinimumSize:], transportProtocol, start, end < len(payload), ident)
		copy(fragment[header.IPv6MinimumSize+header.IPv6FragmentHeaderSize:], payload[start:end])
		fragments = append(fragments, fragment)
	}
	return fragments, true
}

func encodeIPv6FragmentHeader(target []byte, nextHeader uint8, offset int, more bool, ident uint32) {
	target[0] = nextHeader
	target[1] = 0
	value := uint16(offset)
	if more {
		value |= 1
	}
	binary.BigEndian.PutUint16(target[2:], value)
	binary.BigEndian.PutUint32(target[4:], ident)
}

func encodeResetTCP(tcpHdr header.TCP, origTCPHdr header.TCP) {
	fields := header.TCPFields{
		SrcPort:    origTCPHdr.DestinationPort(),
		DstPort:    origTCPHdr.SourcePort(),
		DataOffset: header.TCPMinimumSize,
		Flags:      header.TCPFlagRst,
	}
	if origTCPHdr.Flags()&header.TCPFlagAck != 0 {
		fields.SeqNum = origTCPHdr.AckNumber()
	} else {
		fields.Flags |= header.TCPFlagAck
		ackNumber := origTCPHdr.SequenceNumber() + uint32(len(origTCPHdr.Payload()))
		if origTCPHdr.Flags()&header.TCPFlagSyn != 0 {
			ackNumber++
		}
		if origTCPHdr.Flags()&header.TCPFlagFin != 0 {
			ackNumber++
		}
		fields.AckNum = ackNumber
	}
	tcpHdr.Encode(&fields)
}

func buildRejectICMPv4(ipHdr header.IPv4, code header.ICMPv4Code, source netip.Addr, headroom int) ([]byte, bool) {
	const maxIPData = header.IPv4MinimumProcessableDatagramSize - header.IPv4MinimumSize
	available := maxIPData - header.ICMPv4MinimumSize
	if len(ipHdr) < header.ICMPv4MinimumErrorPayloadSize {
		return nil, false
	}
	payload := []byte(ipHdr)
	if len(payload) > available {
		payload = payload[:available]
	}
	size := header.IPv4MinimumSize + header.ICMPv4MinimumSize + len(payload)
	buffer := make([]byte, headroom+size)
	newIPHdr := header.IPv4(buffer[headroom:])
	newIPHdr.Encode(&header.IPv4Fields{
		TotalLength: uint16(size),
		TTL:         synthesizedTTL,
		Protocol:    uint8(header.ICMPv4ProtocolNumber),
		SrcAddr:     source,
		DstAddr:     ipHdr.SourceAddr(),
	})
	newIPHdr.SetChecksum(^newIPHdr.CalculateChecksum())
	icmpHdr := header.ICMPv4(newIPHdr.Payload())
	icmpHdr.SetType(header.ICMPv4DstUnreachable)
	icmpHdr.SetCode(code)
	copy(icmpHdr.Payload(), payload)
	icmpHdr.SetChecksum(header.ICMPv4Checksum(icmpHdr[:header.ICMPv4MinimumSize], checksum.Checksum(payload, 0)))
	return buffer, true
}

func buildRejectICMPv6(ipHdr header.IPv6, code header.ICMPv6Code, source netip.Addr, headroom int) ([]byte, bool) {
	const maxIPv6Data = header.IPv6MinimumMTU - header.IPv6FixedHeaderSize
	available := maxIPv6Data - header.ICMPv6ErrorHeaderSize
	if available < header.IPv6MinimumSize {
		return nil, false
	}
	payload := []byte(ipHdr)
	if len(payload) > available {
		payload = payload[:available]
	}
	size := header.IPv6MinimumSize + header.ICMPv6DstUnreachableMinimumSize + len(payload)
	buffer := make([]byte, headroom+size)
	newIPHdr := header.IPv6(buffer[headroom:])
	newIPHdr.Encode(&header.IPv6Fields{
		PayloadLength:     uint16(header.ICMPv6DstUnreachableMinimumSize + len(payload)),
		TransportProtocol: header.ICMPv6ProtocolNumber,
		HopLimit:          synthesizedTTL,
		SrcAddr:           source,
		DstAddr:           ipHdr.SourceAddr(),
	})
	icmpHdr := header.ICMPv6(newIPHdr.Payload())
	icmpHdr.SetType(header.ICMPv6DstUnreachable)
	icmpHdr.SetCode(code)
	icmpHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      icmpHdr[:header.ICMPv6DstUnreachableMinimumSize],
		Src:         newIPHdr.SourceAddressSlice(),
		Dst:         newIPHdr.DestinationAddressSlice(),
		PayloadCsum: checksum.Checksum(payload, 0),
		PayloadLen:  len(payload),
	}))
	copy(icmpHdr.Payload(), payload)
	return buffer, true
}

// BuildUnreachable builds an ICMP host/network unreachable reply for packet.
func BuildUnreachable(packet []byte, source netip.Addr, headroom int) ([]byte, bool) {
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		ipHdr := header.IPv4(packet)
		if !ipHdr.IsValid(len(packet)) || ipHdr.FragmentOffset() != 0 {
			return nil, false
		}
		sourceAddr := ipHdr.SourceAddr()
		if sourceAddr.IsUnspecified() || sourceAddr.IsMulticast() {
			return nil, false
		}
		if ipHdr.TransportProtocol() == header.ICMPv4ProtocolNumber {
			if len(ipHdr.Payload()) < header.ICMPv4MinimumSize || header.ICMPv4(ipHdr.Payload()).Type() != header.ICMPv4Echo {
				return nil, false
			}
		}
		replySource := ipHdr.DestinationAddr()
		if source.Is4() {
			replySource = source
		}
		return buildRejectICMPv4(ipHdr, header.ICMPv4HostUnreachable, replySource, headroom)
	case header.IPv6Version:
		ipHdr := header.IPv6(packet)
		if !ipHdr.IsValid(len(packet)) {
			return nil, false
		}
		sourceAddr := ipHdr.SourceAddr()
		if sourceAddr.IsUnspecified() || sourceAddr.IsMulticast() {
			return nil, false
		}
		if ipHdr.TransportProtocol() == header.ICMPv6ProtocolNumber {
			if len(ipHdr.Payload()) < header.ICMPv6MinimumSize || header.ICMPv6(ipHdr.Payload()).Type() != header.ICMPv6EchoRequest {
				return nil, false
			}
		}
		replySource := ipHdr.DestinationAddr()
		if source.Is6() {
			replySource = source
		}
		return buildRejectICMPv6(ipHdr, header.ICMPv6NetworkUnreachable, replySource, headroom)
	default:
		return nil, false
	}
}

func goNewBufferSize(options N.ReadWaitOptions, size int) *buf.Buffer {
	buffer := buf.NewSize(options.FrontHeadroom + size + options.RearHeadroom)
	if options.FrontHeadroom > 0 {
		buffer.Resize(options.FrontHeadroom, 0)
	}
	if options.RearHeadroom > 0 {
		buffer.Reserve(options.RearHeadroom)
	}
	return buffer
}
