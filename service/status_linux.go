package service

import (
	"context"
	"net"
	"os"
)

// This is an implementation of sd_notify(3) for systemd.service(5).

type statusNotifier struct {
	notifyConn *net.UnixConn
}

func newStatusNotifier(ctx context.Context) statusNotifier {
	path := os.Getenv("NOTIFY_SOCKET")
	if path == "" || path[0] != '/' && path[0] != '@' {
		return statusNotifier{}
	}

	var d net.Dialer
	c, err := d.DialUnix(ctx, "unixgram", nil, &net.UnixAddr{
		Name: path,
		Net:  "unixgram",
	})
	if err != nil {
		return statusNotifier{}
	}
	return statusNotifier{
		notifyConn: c,
	}
}

func (sn statusNotifier) Close() error {
	if sn.notifyConn != nil {
		return sn.notifyConn.Close()
	}
	return nil
}

func (sn statusNotifier) Ready() {
	if sn.notifyConn != nil {
		sn.notifyConn.Write([]byte("READY=1"))
	}
}

func (sn statusNotifier) Stopping() {
	if sn.notifyConn != nil {
		sn.notifyConn.Write([]byte("STOPPING=1"))
	}
}
