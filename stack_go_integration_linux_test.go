//go:build linux && !android

package tun

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"

	"github.com/stretchr/testify/require"
)

// These tests drive the go stack with the real kernel TCP/UDP stack through a
// TUN device. They need CAP_NET_ADMIN; run them unprivileged with
//
//	unshare -rn go test -run TestGoStackKernel .
var goKernelInterfaceIndex atomic.Int32

func newGoKernelStack(t *testing.T, handler Handler, gso bool, multiQueue bool) netip.Addr {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires CAP_NET_ADMIN (try: unshare -rn go test -run TestGoStackKernel)")
	}
	index := goKernelInterfaceIndex.Add(1)
	options := Options{
		Name:         fmt.Sprintf("gostack%d", index),
		MTU:          1500,
		GSO:          gso,
		MultiQueue:   multiQueue,
		Inet4Address: []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 18, byte(index), 1}), 30)},
		Logger:       logger.NOP(),
	}
	device, err := New(options)
	require.NoError(t, err)
	stack, err := NewStack("go", StackOptions{
		Context:    context.Background(),
		Tun:        device,
		TunOptions: options,
		Handler:    handler,
		Logger:     logger.NOP(),
		UDPTimeout: time.Minute,
	})
	require.NoError(t, err)
	require.NoError(t, stack.Start())
	t.Cleanup(func() {
		require.NoError(t, stack.Close())
		require.NoError(t, device.Close())
	})
	goStack := stack.(*Go)
	if multiQueue {
		require.Greater(t, len(goStack.engines), 1, "multi-queue device should start one engine per queue")
	} else {
		require.Len(t, goStack.engines, 1)
	}
	require.Equal(t, gso, goStack.engines[0].platformIO.(*goLinuxIO).device.vnetHeader)
	return netip.AddrFrom4([4]byte{198, 18, byte(index), 2})
}

func goKernelEchoHandler() *testHandler {
	return &testHandler{
		tcp: func(_ context.Context, conn net.Conn, _ M.Metadata) error {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
			return nil
		},
		udp: func(_ context.Context, _ netip.AddrPort, buffer *buf.Buffer, metadata M.Metadata, init func(N.PacketConn) N.PacketWriter) {
			_ = init(nil).WritePacket(buffer, metadata.Destination)
		},
	}
}

func testGoKernelTCPBulk(t *testing.T, gso bool, multiQueue bool) {
	remote := newGoKernelStack(t, goKernelEchoHandler(), gso, multiQueue)
	conn, err := net.DialTimeout("tcp4", netip.AddrPortFrom(remote, 80).String(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))
	payload := make([]byte, 32<<20)
	_, err = rand.Read(payload)
	require.NoError(t, err)
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := conn.Write(payload)
		if writeErr == nil {
			writeErr = conn.(*net.TCPConn).CloseWrite()
		}
		writeDone <- writeErr
	}()
	hash := sha256.New()
	n, err := io.Copy(hash, conn)
	require.NoError(t, err)
	require.NoError(t, <-writeDone)
	require.Equal(t, int64(len(payload)), n)
	expected := sha256.Sum256(payload)
	require.True(t, bytes.Equal(expected[:], hash.Sum(nil)), "echoed data differs")
}

func TestGoStackKernelTCP(t *testing.T) {
	t.Run("plain", func(t *testing.T) { testGoKernelTCPBulk(t, false, false) })
	t.Run("gso", func(t *testing.T) { testGoKernelTCPBulk(t, true, false) })
	t.Run("multiqueue", func(t *testing.T) { testGoKernelTCPBulk(t, true, true) })
}

func TestGoStackKernelTCPParallel(t *testing.T) {
	remote := newGoKernelStack(t, goKernelEchoHandler(), true, true)
	const connections = 32
	errs := make(chan error, connections)
	for i := 0; i < connections; i++ {
		go func() {
			conn, err := net.DialTimeout("tcp4", netip.AddrPortFrom(remote, 80).String(), 5*time.Second)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
			payload := make([]byte, 1<<20)
			_, _ = rand.Read(payload)
			go func() {
				_, _ = conn.Write(payload)
				_ = conn.(*net.TCPConn).CloseWrite()
			}()
			received, err := io.ReadAll(conn)
			if err == nil && !bytes.Equal(received, payload) {
				err = fmt.Errorf("echo mismatch: %d bytes", len(received))
			}
			errs <- err
		}()
	}
	for i := 0; i < connections; i++ {
		require.NoError(t, <-errs)
	}
}

func TestGoStackKernelUDP(t *testing.T) {
	remote := newGoKernelStack(t, goKernelEchoHandler(), true, false)
	conn, err := net.Dial("udp4", netip.AddrPortFrom(remote, 53).String())
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	for _, size := range []int{1, 512, 1400, 4000, 60000} {
		payload := make([]byte, size)
		_, _ = rand.Read(payload)
		_, err = conn.Write(payload)
		require.NoError(t, err)
		reply := make([]byte, 65535)
		n, err := conn.Read(reply)
		require.NoError(t, err, "size %d", size)
		require.Equal(t, payload, reply[:n], "size %d", size)
	}
}
