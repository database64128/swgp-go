//go:build darwin || dragonfly || freebsd || netbsd || openbsd || solaris || zos

package conn

import "golang.org/x/sys/unix"

const alignedSizeofCmsghdr = (unix.SizeofCmsghdr + cmsgAlignTo - 1) & ^(cmsgAlignTo - 1)
