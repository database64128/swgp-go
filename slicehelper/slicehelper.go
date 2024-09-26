package slicehelper

// Extend extends the input slice by n elements. head is the full extended
// slice, while tail is the appended part. If the original slice has sufficient
// capacity no allocation is performed.
func Extend[S ~[]E, E any](in S, n int) (head, tail S) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make(S, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
