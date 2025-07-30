//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows && !zos

package conn

const socketControlMessageBufferSize = 0

func parseSocketControlMessage(_ []byte) (SocketControlMessage, error) {
	return SocketControlMessage{}, nil
}

func (SocketControlMessage) appendTo(b []byte) []byte {
	return b
}
