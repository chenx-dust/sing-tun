//go:build with_gvisor

package tun

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/header"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/link/pipe"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv4"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/udp"
	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

// gVisor throughput benchmarks for the stack configuration used by this
// library (NewGVisorStack + TCP/UDP forwarders).
//
// TCP runs two stacks joined by an in-process pipe: a client stack dials, and
// the server stack is the sing-tun forwarder. Both ends therefore execute
// gVisor TCP. Linux TUN normally also enables RX checksum offload, which these
// benches turn on; TX checksums stay on, matching the library default.
//
// "default" uses NewGVisorStack as-is (gVisor windows: 1 MiB, autotuned to
// 4 MiB) and a 1500-byte MTU. "mtu64k" keeps those windows and raises the MTU
// to 64 KiB. "large" also pins the windows at 4 MiB.

const (
	gvisorBenchMTU      = 1500
	gvisorBenchLargeMTU = 64 << 10
	gvisorBenchChunk    = 32 << 10
	gvisorBenchLargeBuf = 4 << 20
	gvisorUDPPayload    = 1400
)

var (
	gvisorClientAddr = tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	gvisorServerAddr = tcpip.AddrFrom4([4]byte{10, 0, 0, 2})
)

type rxOffloadEndpoint struct {
	stack.LinkEndpoint
}

func (e rxOffloadEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.LinkEndpoint.Capabilities() | stack.CapabilityRXChecksumOffload
}

func newBenchStack(b *testing.B, ep stack.LinkEndpoint, addr tcpip.Address, bufSize int) *stack.Stack {
	b.Helper()
	s, err := NewGVisorStack(rxOffloadEndpoint{ep})
	if err != nil {
		b.Fatal(err)
	}
	if bufSize > 0 {
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPReceiveBufferSizeRangeOption{
			Min: bufSize, Default: bufSize, Max: bufSize,
		}); err != nil {
			b.Fatal(err)
		}
		if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpip.TCPSendBufferSizeRangeOption{
			Min: bufSize, Default: bufSize, Max: bufSize,
		}); err != nil {
			b.Fatal(err)
		}
	}
	protoAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: 24,
		},
	}
	if tcpipErr := s.AddProtocolAddress(DefaultNIC, protoAddr, stack.AddressProperties{}); tcpipErr != nil {
		b.Fatal(tcpipErr)
	}
	b.Cleanup(func() { s.Close() })
	return s
}

func benchTCPStacks(b *testing.B, mtu uint32, bufSize int) (clientStack, serverStack *stack.Stack) {
	b.Helper()
	clientEP, serverEP := pipe.New("", "", mtu)
	return newBenchStack(b, clientEP, gvisorClientAddr, bufSize), newBenchStack(b, serverEP, gvisorServerAddr, bufSize)
}

func dialBenchTCP(b *testing.B, clientStack *stack.Stack) *gonet.TCPConn {
	b.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := gonet.DialContextTCP(ctx, clientStack, tcpip.FullAddress{
		Addr: gvisorServerAddr,
		Port: 443,
	}, ipv4.ProtocolNumber)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = conn.Close() })
	return conn
}

func BenchmarkGVisorTCPUpload(b *testing.B) {
	for _, tc := range []struct {
		name    string
		mtu     uint32
		bufSize int
		conns   int
	}{
		{"default/1conn", gvisorBenchMTU, 0, 1},
		{"default/4conn", gvisorBenchMTU, 0, 4},
		{"mtu64k/1conn", gvisorBenchLargeMTU, 0, 1},
		{"large/1conn", gvisorBenchLargeMTU, gvisorBenchLargeBuf, 1},
		{"large/4conn", gvisorBenchLargeMTU, gvisorBenchLargeBuf, 4},
	} {
		b.Run(tc.name, func(b *testing.B) {
			benchmarkTCP(b, tc.mtu, tc.bufSize, tc.conns, true)
		})
	}
}

func BenchmarkGVisorTCPDownload(b *testing.B) {
	for _, tc := range []struct {
		name    string
		mtu     uint32
		bufSize int
		conns   int
	}{
		{"default/1conn", gvisorBenchMTU, 0, 1},
		{"default/4conn", gvisorBenchMTU, 0, 4},
		{"mtu64k/1conn", gvisorBenchLargeMTU, 0, 1},
		{"large/1conn", gvisorBenchLargeMTU, gvisorBenchLargeBuf, 1},
		{"large/4conn", gvisorBenchLargeMTU, gvisorBenchLargeBuf, 4},
	} {
		b.Run(tc.name, func(b *testing.B) {
			benchmarkTCP(b, tc.mtu, tc.bufSize, tc.conns, false)
		})
	}
}

func benchmarkTCP(b *testing.B, mtu uint32, bufSize, conns int, upload bool) {
	b.Helper()
	clientStack, serverStack := benchTCPStacks(b, mtu, bufSize)
	accepted := make(chan net.Conn, conns)
	forwarder := NewTCPForwarder(context.Background(), serverStack, &testHandler{
		tcp: func(_ context.Context, c net.Conn, _ M.Metadata) error {
			accepted <- c
			if upload {
				_, _ = io.Copy(io.Discard, c)
			}
			return nil
		},
	})
	serverStack.SetTransportProtocolHandler(tcp.ProtocolNumber, forwarder.HandlePacket)

	clients := make([]net.Conn, conns)
	servers := make([]net.Conn, conns)
	for i := 0; i < conns; i++ {
		clients[i] = dialBenchTCP(b, clientStack)
		select {
		case servers[i] = <-accepted:
		case <-time.After(5 * time.Second):
			b.Fatal("timed out waiting for forwarded connection")
		}
		srv := servers[i]
		b.Cleanup(func() { _ = srv.Close() })
		if !upload {
			go func(c net.Conn) { _, _ = io.Copy(io.Discard, c) }(clients[i])
		}
	}

	payload := make([]byte, gvisorBenchChunk)
	writers := clients
	if !upload {
		writers = servers
	}
	b.SetBytes(int64(gvisorBenchChunk))
	b.ReportAllocs()
	b.ResetTimer()
	if conns == 1 {
		for i := 0; i < b.N; i++ {
			if _, err := writers[0].Write(payload); err != nil {
				b.Fatal(err)
			}
		}
		return
	}

	counts := splitIters(b.N, conns)
	var wg sync.WaitGroup
	errCh := make(chan error, conns)
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < counts[i]; j++ {
				if _, err := writers[i].Write(payload); err != nil {
					errCh <- err
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			b.Fatal(err)
		}
	}
}

func splitIters(n, parts int) []int {
	counts := make([]int, parts)
	base := n / parts
	for i := 0; i < parts; i++ {
		counts[i] = base
	}
	counts[0] += n - base*parts
	return counts
}

func BenchmarkGVisorUDPEcho(b *testing.B) {
	clientStack, serverStack := benchTCPStacks(b, gvisorBenchMTU, 0)
	serverStack.SetTransportProtocolHandler(udp.ProtocolNumber, NewUDPForwarder(context.Background(), serverStack, &testHandler{
		udp: func(_ context.Context, _ netip.AddrPort, packet *buf.Buffer, metadata M.Metadata, init func(N.PacketConn) N.PacketWriter) {
			_ = init(nil).WritePacket(packet, metadata.Destination)
		},
	}).HandlePacket)

	conn, err := gonet.DialUDP(clientStack,
		&tcpip.FullAddress{Addr: gvisorClientAddr, Port: 12345},
		&tcpip.FullAddress{Addr: gvisorServerAddr, Port: 53},
		ipv4.ProtocolNumber,
	)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = conn.Close() })

	payload := make([]byte, gvisorUDPPayload)
	readBuf := make([]byte, gvisorUDPPayload+1)
	if _, err = conn.Write(payload); err != nil {
		b.Fatal(err)
	}
	if _, err = conn.Read(readBuf); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(gvisorUDPPayload)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err = conn.Write(payload); err != nil {
			b.Fatal(err)
		}
		n, err := conn.Read(readBuf)
		if err != nil {
			b.Fatal(err)
		}
		if n != gvisorUDPPayload {
			b.Fatalf("short read: %d", n)
		}
	}
}

func BenchmarkGVisorUDPIngress(b *testing.B) {
	ep := channel.New(1024, gvisorBenchMTU, "")
	s := newBenchStack(b, ep, gvisorServerAddr, 0)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, NewUDPForwarder(context.Background(), s, &testHandler{
		udp: func(_ context.Context, _ netip.AddrPort, packet *buf.Buffer, _ M.Metadata, _ func(N.PacketConn) N.PacketWriter) {
			packet.Release()
		},
	}).HandlePacket)

	packet := udpPacket(netip.AddrFrom4(gvisorClientAddr.As4()), netip.AddrFrom4(gvisorServerAddr.As4()), 53, make([]byte, gvisorUDPPayload))
	b.SetBytes(gvisorUDPPayload)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packet),
		})
		ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
		pkt.DecRef()
	}
}
