//go:build !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package netiface

import (
	"context"
	"sync/atomic"

	"github.com/database64128/swgp-go/conn"
	"github.com/database64128/swgp-go/tslog"
)

func (*PickerConfig) newPicker(*tslog.Logger) (*Picker, error) {
	return nil, ErrPickerUnsupported
}

type picker struct{}

func (picker) start(context.Context) error {
	return ErrPickerUnsupported
}

func (picker) stop() error {
	return ErrPickerUnsupported
}

func (picker) default4() *atomic.Pointer[conn.Pktinfo] {
	panic(ErrPickerUnsupported)
}

func (picker) default6() *atomic.Pointer[conn.Pktinfo] {
	panic(ErrPickerUnsupported)
}
