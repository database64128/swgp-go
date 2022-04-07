//go:build !linux

package conn

// UDPOOBBufferSize specifies the size of buffer to allocate for receiving OOB data
// when calling the ReadMsgUDP method on a *net.UDPConn returned by this package's ListenUDP function.
const UDPOOBBufferSize = 0

// GetOobForCache filters out irrelevant OOB messages
// and returns only IP_PKTINFO or IPV6_PKTINFO socket control messages.
//
// Errors returned by this function can be safely ignored,
// or printed as debug logs.
func GetOobForCache(clientOob []byte) ([]byte, error) {
	return nil, nil
}
