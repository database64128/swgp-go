package netiface

import (
	"sync/atomic"

	"github.com/database64128/swgp-go/conn"
	"github.com/database64128/swgp-go/tslog"
)

func (*PickerConfig) newPicker(_ *tslog.Logger) (*Picker, error) {
	return nil, ErrPickerUnsupported
}

type picker struct{}

func (picker) requestPoll() {
	panic(ErrPickerUnsupported)
}

func (picker) default4() *atomic.Pointer[conn.Pktinfo] {
	panic(ErrPickerUnsupported)
}

func (picker) default6() *atomic.Pointer[conn.Pktinfo] {
	panic(ErrPickerUnsupported)
}
