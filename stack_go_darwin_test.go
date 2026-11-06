package tun

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const goTestPacketPrefixLength = PacketOffset

func newGoTestSocketPair(t *testing.T) (tunFd int, peerFd int) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	require.NoError(t, err)
	return fds[0], fds[1]
}

func goTestPacketPrefix(packet []byte) []byte {
	if packet[0]>>4 == 6 {
		return []byte{0, 0, 0, unix.AF_INET6}
	}
	return []byte{0, 0, 0, unix.AF_INET}
}
