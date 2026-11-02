//go:build linux

package tun

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// goTestPeer stands in for the kernel side of the TUN: the go stack gets one end
// of a SOCK_SEQPACKET pair as its "tun fd" and the test reads/writes IP packets
// on the other end.
type goTestPeer struct {
	fd int
}

func newGoTestStack(t *testing.T, handler *testHandler) (*Go, *goTestPeer) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	require.NoError(t, unix.SetNonblock(fds[0], true))
	device := &NativeTun{tunFd: fds[0], tunFile: os.NewFile(uintptr(fds[0]), "tun")}
	v, err := NewStack("go", StackOptions{
		Context:     context.Background(),
		Tun:         device,
		Handler:     handler,
		Logger:      logger.NOP(),
		ICMPTimeout: 50 * time.Millisecond,
		TunOptions: Options{
			MTU:          1500,
			Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
			Inet6Address: []netip.Prefix{netip.MustParsePrefix("fd00::1/126")},
		},
	})
	require.NoError(t, err)
	stack := v.(*Go)
	require.NoError(t, stack.Start())
	peer := &goTestPeer{fd: fds[1]}
	t.Cleanup(func() {
		require.NoError(t, stack.Close())
		_ = device.tunFile.Close()
		_ = unix.Close(peer.fd)
	})
	return stack, peer
}

func (p *goTestPeer) write(t *testing.T, packet []byte) {
	t.Helper()
	_, err := unix.Write(p.fd, packet)
	require.NoError(t, err)
}

func (p *goTestPeer) read(t *testing.T) []byte {
	t.Helper()
	require.NoError(t, unix.SetsockoptTimeval(p.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 3}))
	buffer := make([]byte, 65535)
	n, err := unix.Read(p.fd, buffer)
	require.NoError(t, err, "timed out waiting for a packet from the go stack")
	return buffer[:n]
}

// readTCP skips anything that is not a TCP segment (the stack sends nothing
// else here, but keep the helper tolerant).
func (p *goTestPeer) readTCP(t *testing.T) []byte {
	t.Helper()
	for {
		packet := p.read(t)
		if packet[0]>>4 == 4 && packet[9] == 6 {
			return packet
		}
	}
}

func goTestTCPSegment(source, target netip.Addr, sourcePort, targetPort uint16, seq, ack uint32, flags byte, options []byte, payload []byte) []byte {
	headerLength := 20 + len(options)
	segment := make([]byte, headerLength+len(payload))
	binary.BigEndian.PutUint16(segment, sourcePort)
	binary.BigEndian.PutUint16(segment[2:], targetPort)
	binary.BigEndian.PutUint32(segment[4:], seq)
	binary.BigEndian.PutUint32(segment[8:], ack)
	segment[12] = byte(headerLength/4) << 4
	segment[13] = flags
	binary.BigEndian.PutUint16(segment[14:], 65535)
	copy(segment[20:], options)
	copy(segment[headerLength:], payload)
	return transportPacket(source, target, 6, segment)
}

func TestGoStackTCP(t *testing.T) {
	received := make(chan string, 1)
	handler := &testHandler{tcp: func(_ context.Context, conn net.Conn, metadata M.Metadata) error {
		defer conn.Close()
		if metadata.Destination.String() != "1.1.1.1:443" {
			received <- "bad destination " + metadata.Destination.String()
			return nil
		}
		buffer := make([]byte, 5)
		_, err := io.ReadFull(conn, buffer)
		if err != nil {
			received <- err.Error()
			return nil
		}
		received <- string(buffer)
		_, _ = conn.Write([]byte("world"))
		return nil
	}}
	_, peer := newGoTestStack(t, handler)
	client, server := netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("1.1.1.1")
	const clientISN = 1000
	mss := []byte{2, 4, 0x05, 0xb4}
	peer.write(t, goTestTCPSegment(client, server, 40000, 443, clientISN, 0, 0x02, mss, nil))

	// The SYN-ACK is deferred until the handler first reads the connection.
	synAck := peer.readTCP(t)
	tcp := synAck[20:]
	require.Equal(t, byte(0x12), tcp[13]&0x12, "expected SYN-ACK")
	require.Equal(t, uint32(clientISN+1), binary.BigEndian.Uint32(tcp[8:]))
	serverISN := binary.BigEndian.Uint32(tcp[4:])

	peer.write(t, goTestTCPSegment(client, server, 40000, 443, clientISN+1, serverISN+1, 0x10, nil, nil))
	peer.write(t, goTestTCPSegment(client, server, 40000, 443, clientISN+1, serverISN+1, 0x18, nil, []byte("hello")))
	select {
	case data := <-received:
		require.Equal(t, "hello", data)
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not receive data")
	}
	for {
		segment := peer.readTCP(t)
		tcp = segment[20:]
		payload := tcp[int(tcp[12]>>4)*4:]
		if len(payload) == 0 {
			continue
		}
		require.Equal(t, "world", string(payload))
		require.Equal(t, serverISN+1, binary.BigEndian.Uint32(tcp[4:]))
		break
	}
}

func TestGoStackTCPHandlerErrorResets(t *testing.T) {
	handler := &testHandler{tcp: func(context.Context, net.Conn, M.Metadata) error {
		return io.EOF
	}}
	_, peer := newGoTestStack(t, handler)
	client, server := netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("1.1.1.1")
	peer.write(t, goTestTCPSegment(client, server, 40001, 443, 1, 0, 0x02, nil, nil))
	segment := peer.readTCP(t)
	require.NotZero(t, segment[20+13]&0x04, "expected RST")
}

func TestGoStackUDP(t *testing.T) {
	type datagram struct {
		key     netip.AddrPort
		payload string
		meta    M.Metadata
		writer  N.PacketWriter
	}
	datagrams := make(chan datagram, 1)
	handler := &testHandler{udp: func(_ context.Context, key netip.AddrPort, buffer *buf.Buffer, metadata M.Metadata, init func(N.PacketConn) N.PacketWriter) {
		datagrams <- datagram{key: key, payload: string(buffer.Bytes()), meta: metadata, writer: init(nil)}
		buffer.Release()
	}}
	_, peer := newGoTestStack(t, handler)
	client, server := netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("8.8.8.8")
	peer.write(t, udpPacket(client, server, 53, []byte("query")))
	var received datagram
	select {
	case received = <-datagrams:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not receive datagram")
	}
	require.Equal(t, "query", received.payload)
	require.Equal(t, netip.AddrPortFrom(client, 12345), received.key)
	require.Equal(t, "8.8.8.8:53", received.meta.Destination.String())

	reply := buf.NewSize(64)
	reply.Resize(N.CalculateFrontHeadroom(received.writer), 0)
	_, _ = reply.WriteString("answer")
	require.NoError(t, received.writer.WritePacket(reply, M.SocksaddrFrom(server, 53)))
	packet := peer.read(t)
	require.Equal(t, byte(17), packet[9])
	require.Equal(t, server, netip.AddrFrom4([4]byte(packet[12:16])))
	require.Equal(t, client, netip.AddrFrom4([4]byte(packet[16:20])))
	require.Equal(t, uint16(53), binary.BigEndian.Uint16(packet[20:]))
	require.Equal(t, uint16(12345), binary.BigEndian.Uint16(packet[22:]))
	require.Equal(t, "answer", string(packet[28:]))
	require.Zero(t, mipsTestChecksum(packet[:20]))

	// A writer that ignores FrontHeadroom must still work.
	require.NoError(t, received.writer.WritePacket(buf.As([]byte("again")).ToOwned(), M.SocksaddrFrom(server, 53)))
	packet = peer.read(t)
	require.Equal(t, "again", string(packet[28:]))
}

func TestGoStackICMPEchoLocal(t *testing.T) {
	_, peer := newGoTestStack(t, &testHandler{})
	client, local := netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("198.18.0.1")
	echo := []byte{8, 0, 0, 0, 0, 1, 0, 1, 'p', 'i', 'n', 'g'}
	peer.write(t, transportPacket(client, local, 1, echo))
	reply := peer.read(t)
	require.Equal(t, byte(1), reply[9])
	require.Equal(t, byte(0), reply[20], "expected echo reply")
	require.Equal(t, local, netip.AddrFrom4([4]byte(reply[12:16])))
	require.Equal(t, "ping", string(reply[28:]))
}

func TestGoStackICMPReset(t *testing.T) {
	handler := &testHandler{prepare: func(DirectRouteContext) (DirectRouteDestination, error) {
		return nil, ErrReset
	}}
	_, peer := newGoTestStack(t, handler)
	client, remote := netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("9.9.9.9")
	echo := []byte{8, 0, 0, 0, 0, 1, 0, 1, 'p', 'i', 'n', 'g'}
	peer.write(t, transportPacket(client, remote, 1, echo))
	reply := peer.read(t)
	require.Equal(t, byte(1), reply[9])
	require.Equal(t, byte(3), reply[20], "expected destination unreachable")
}

func TestGoStackICMPRemoteEchoWithoutRoute(t *testing.T) {
	// PrepareConnection returning (nil, nil) means "no direct route": reply locally.
	_, peer := newGoTestStack(t, &testHandler{})
	client, remote := netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("9.9.9.9")
	echo := []byte{8, 0, 0, 0, 0, 1, 0, 1, 'p', 'i', 'n', 'g'}
	peer.write(t, transportPacket(client, remote, 1, echo))
	reply := peer.read(t)
	require.Equal(t, byte(0), reply[20], "expected echo reply")
	require.Equal(t, remote, netip.AddrFrom4([4]byte(reply[12:16])))
}
