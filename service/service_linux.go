package service

// vecSize is the number of iovec used in a sendmmsg relay session.
//
// iperf3 tests show that 64 is more than enough.
const (
	vecSize  = 64
	sizeMask = 63
)
