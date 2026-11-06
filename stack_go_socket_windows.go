package tun

import (
	"syscall"
	"unsafe"

	"github.com/metacubex/sing-tun/internal/afd"
	E "github.com/metacubex/sing/common/exceptions"

	"golang.org/x/sys/windows"
)

const (
	goSpliceDuplicatesSocket = false
	goSocketFIONBIO          = 0x8004667e
	goSocketReceiveBuffer    = 4 << 20
)

type goIOVector = windows.WSABuf

type goSocket struct {
	handle windows.Handle
	entry  *goAFDEntry
}

type goAFDEntry struct {
	ioStatusBlock windows.IO_STATUS_BLOCK
	pollInfo      afd.PollInfo
	baseHandle    windows.Handle
	token         uint32
	interest      uint8
	armed         bool
	cancelled     bool
	pinner        goPinner
}

func goSpliceSocket(conn syscall.Conn) (goSocket, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return goSocket{}, err
	}
	var handle windows.Handle
	err = rawConn.Control(func(fd uintptr) {
		handle = windows.Handle(fd)
	})
	if err != nil {
		return goSocket{}, err
	}
	var (
		mode          uint32 = 1
		bytesReturned uint32
	)
	err = windows.WSAIoctl(handle, goSocketFIONBIO, (*byte)(unsafe.Pointer(&mode)), uint32(unsafe.Sizeof(mode)), nil, 0, &bytesReturned, nil, 0)
	if err != nil {
		return goSocket{}, E.Cause(err, "set socket non-blocking")
	}
	// Without an explicit receive buffer the socket advertises 64 KiB, and readiness-driven reads
	// then cost a thread wake-up per window; the runtime poller hid this behind posted overlapped reads.
	err = windows.SetsockoptInt(handle, windows.SOL_SOCKET, windows.SO_RCVBUF, goSocketReceiveBuffer)
	if err != nil {
		return goSocket{}, E.Cause(err, "set socket receive buffer")
	}
	return goSocket{handle: handle}, nil
}

func (s *goSocket) close() {
}

func (s *goSocket) shutdownWrite() {
	windows.Shutdown(s.handle, windows.SHUT_WR)
}

func goIovecsFromSegments(iovecs []goIOVector, segments [][]byte) []goIOVector {
	iovecs = iovecs[:0]
	for _, segment := range segments {
		if len(segment) == 0 {
			continue
		}
		iovecs = append(iovecs, windows.WSABuf{Len: uint32(len(segment)), Buf: &segment[0]})
	}
	return iovecs
}

func goSocketWouldBlock(errno syscall.Errno) bool {
	return errno == windows.WSAEWOULDBLOCK || errno == windows.WSAEINTR
}

func (s *goSocket) readVector(iovecs []goIOVector) (int, syscall.Errno) {
	var (
		received uint32
		flags    uint32
	)
	err := windows.WSARecv(s.handle, &iovecs[0], uint32(len(iovecs)), &received, &flags, nil, nil)
	if err != nil {
		return 0, err.(syscall.Errno)
	}
	return int(received), 0
}

func (s *goSocket) writeVector(iovecs []goIOVector) (int, syscall.Errno) {
	var sent uint32
	err := windows.WSASend(s.handle, &iovecs[0], uint32(len(iovecs)), &sent, 0, nil, nil)
	if err != nil {
		return 0, err.(syscall.Errno)
	}
	return int(sent), 0
}
