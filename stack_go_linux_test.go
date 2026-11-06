package tun

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const goTestPacketPrefixLength = 0

func newGoTestSocketPair(t *testing.T) (tunFd int, peerFd int) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	return fds[0], fds[1]
}

func goTestPacketPrefix(packet []byte) []byte {
	return nil
}
