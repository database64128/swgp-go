//go:build dragonfly || freebsd || linux || (netbsd && !arm && !arm64) || (openbsd && !arm)

package conn

import "golang.org/x/sys/unix"

const cmsgAlignTo = unix.SizeofPtr
