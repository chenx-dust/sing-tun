package tun

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func (s *goSocket) writeVector(iovecs []unix.Iovec) (int, syscall.Errno) {
	var message unix.Msghdr
	message.Iov = &iovecs[0]
	message.SetIovlen(len(iovecs))
	//nolint:staticcheck
	n, _, errno := unix.RawSyscall(unix.SYS_SENDMSG, uintptr(s.fd), uintptr(unsafe.Pointer(&message)), goSocketSendFlags)
	return int(n), errno
}
