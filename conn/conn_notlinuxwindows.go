//go:build !linux && !windows

package conn

import "go.uber.org/zap"

// SocketControlMessageBufferSize specifies the buffer size for receiving socket control messages.
const SocketControlMessageBufferSize = 0

// On Linux and Windows, UpdatePktinfoCache filters out irrelevant socket control messages,
// saves IP_PKTINFO or IPV6_PKTINFO socket control messages to the pktinfo cache,
// and returns the updated pktinfo cache slice.
//
// The returned pktinfo cache is unchanged if no relevant control messages are found.
//
// On other platforms, this is a no-op.
func UpdatePktinfoCache(pktinfoCache, cmsgs []byte, logger *zap.Logger) ([]byte, error) {
	return nil, nil
}
