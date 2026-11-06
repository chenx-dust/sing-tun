//go:build go1.21

package tun

import "runtime"

type goPinner = runtime.Pinner
