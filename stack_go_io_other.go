//go:build !(linux || windows || darwin)

package tun

import (
	"syscall"

	E "github.com/metacubex/sing/common/exceptions"
)

const goEngineInlineTransmit = false

func newGoPlatformQueues(stack *Go) ([]goPlatformIO, error) {
	return nil, E.New("go: unsupported platform")
}

func goFatalReadError(err error) bool {
	return true
}

const goSpliceDuplicatesSocket = false

type goIOVector struct{}

type goSocket struct{}

func goSpliceSocket(conn syscall.Conn) (goSocket, error) {
	return goSocket{}, E.New("go: splice not supported")
}

func (s *goSocket) close() {
}

func (s *goSocket) readVector(iovecs []goIOVector) (int, syscall.Errno) {
	return 0, syscall.ENOSYS
}

func (s *goSocket) writeVector(iovecs []goIOVector) (int, syscall.Errno) {
	return 0, syscall.ENOSYS
}

func (s *goSocket) shutdownWrite() {
}

func goIovecsFromSegments(iovecs []goIOVector, segments [][]byte) []goIOVector {
	return iovecs[:0]
}

func goSocketWouldBlock(errno syscall.Errno) bool {
	return errno == syscall.EAGAIN || errno == syscall.EWOULDBLOCK || errno == syscall.EINTR
}
