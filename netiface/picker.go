package netiface

import (
	"errors"
	"sync/atomic"

	"github.com/database64128/swgp-go/conn"
	"github.com/database64128/swgp-go/tslog"
)

// PickerUnsupportedError is returned when the platform is not supported by the interface picker.
type PickerUnsupportedError struct{}

func (PickerUnsupportedError) Error() string {
	return "interface picker is not supported on this platform"
}

func (PickerUnsupportedError) Is(target error) bool {
	return target == errors.ErrUnsupported
}

var ErrPickerUnsupported = PickerUnsupportedError{}

// PickerConfig is the configuration for the interface picker.
type PickerConfig struct{}

// NewPicker returns a new interface picker.
func (c *PickerConfig) NewPicker(logger *tslog.Logger) (*Picker, error) {
	return c.newPicker(logger)
}

// Picker is implemented on supported platforms to discover and pick default physical network interfaces.
//
// This is useful for preventing routing loops, when a default route to a virtual tunnel interface is configured.
type Picker struct {
	picker
}

// RequestPoll requests the picker to poll for changes in the network interfaces.
//
// Depending on the implementation, this may be a no-op.
func (p *Picker) RequestPoll() {
	p.requestPoll()
}

// Default4 returns the first IPv4 address and the interface index of the first
// physical network interface with an IPv4 default route.
//
// The returned pointer is guaranteed to be non-nil, but the value may be zero,
// indicating that no suitable interface was found.
func (p *Picker) Default4() *atomic.Pointer[conn.Pktinfo] {
	return p.default4()
}

// Default6 returns the first IPv6 address and the interface index of the first
// physical network interface with an IPv6 default route.
//
// The returned pointer is guaranteed to be non-nil, but the value may be zero,
// indicating that no suitable interface was found.
func (p *Picker) Default6() *atomic.Pointer[conn.Pktinfo] {
	return p.default6()
}
