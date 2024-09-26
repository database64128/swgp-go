//go:build !darwin && !linux && !windows

package conn

const socketControlMessageBufferSize = 0

func parseSocketControlMessage(_ []byte) (SocketControlMessage, error) {
	return SocketControlMessage{}, nil
}

func (SocketControlMessage) appendTo(b []byte) []byte {
	return b
}
