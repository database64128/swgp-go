package slicehelper

import "slices"

// Extend extends the input slice by n elements. head is the full extended
// slice, while tail is the appended part. If the original slice has sufficient
// capacity no allocation is performed.
func Extend[S ~[]E, E any](in S, n int) (head, tail S) {
	head = slices.Grow(in, n)[:len(in)+n]
	return head, head[len(in):]
}
