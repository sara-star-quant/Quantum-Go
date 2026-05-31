package protocol

// AppendDatagramDataHeader appends the 14-byte common DATA-frame header for h to
// dst and returns the extended slice. It forces h.Type to DatagramFrameData. The
// header is written directly into the (grown) dst with no temporary buffer - the
// `append(dst, make(...)...)` form is special-cased by the compiler to avoid
// allocating the make'd slice - so with a dst that has spare capacity this adds no
// heap allocation. The datagram send hot path uses it to build a frame header in a
// reusable buffer before sealing the payload in place after it.
func AppendDatagramDataHeader(dst []byte, h DatagramHeader) []byte {
	h.Type = DatagramFrameData
	off := len(dst)
	dst = append(dst, make([]byte, DatagramHeaderSize)...)
	putDatagramHeader(dst[off:], h)
	return dst
}
