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
	return goSendmsg(s.fd, &message, goSocketSendFlags)
}

func goSendmsg(fd int, message *unix.Msghdr, flags int) (int, syscall.Errno) {
	n, _, errno := unix.Syscall(unix.SYS_SENDMSG, uintptr(fd), uintptr(unsafe.Pointer(message)), uintptr(flags))
	if errno != 0 {
		return 0, errno
	}
	return int(n), 0
}
