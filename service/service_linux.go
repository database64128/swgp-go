package service

import "github.com/database64128/swgp-go/conn"

// vecSize is the number of iovec used in a sendmmsg relay session.
const (
	vecSize  = conn.UIO_MAXIOV
	sizeMask = vecSize - 1
)
