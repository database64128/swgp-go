//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris || windows || zos

package conn

func cmsgAlign(n int) int {
	return (n + cmsgAlignTo - 1) & ^(cmsgAlignTo - 1)
}
