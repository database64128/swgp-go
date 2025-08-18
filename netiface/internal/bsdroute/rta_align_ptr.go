//go:build dragonfly || freebsd || openbsd

package bsdroute

import "golang.org/x/sys/unix"

const rtaAlignTo = unix.SizeofPtr
