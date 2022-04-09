//go:build !linux && !windows

package conn

import "go.uber.org/zap"

// UDPOOBBufferSize specifies the size of buffer to allocate for receiving OOB data
// when calling the ReadMsgUDP method on a *net.UDPConn returned by this package's ListenUDP function.
const UDPOOBBufferSize = 0

// UpdateOobCache filters out irrelevant OOB messages, saves
// IP_PKTINFO or IPV6_PKTINFO socket control messages to the OOB cache,
// and returns the updated OOB cache slice.
//
// IP_PKTINFO and IPV6_PKTINFO socket control messages are only supported
// on Linux and Windows.
//
// The returned OOB cache is unchanged if no relevant control messages
// are found.
//
// Errors returned by this function can be safely ignored,
// or printed as debug logs.
func UpdateOobCache(oobCache, oob []byte, logger *zap.Logger) ([]byte, error) {
	return nil, nil
}
