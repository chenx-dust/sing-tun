//go:build !go1.21

package tun

// The heap does not move objects, and goWindowsIO.entries keeps every entry reachable until
// AFD completes or cancels the poll that references it, so pinning is only a formality here.
type goPinner struct{}

func (p *goPinner) Pin(pointer any) {}

func (p *goPinner) Unpin() {}
