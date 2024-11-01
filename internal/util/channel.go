package util

// FiniteValueChannel returns a new read-only buffered channel with all the provided values already pushed into it.
// The channel returned is closed and allows no further writes.
func FiniteValueChannel[T any](val ...T) <-chan T {
	var ch = make(chan T, len(val)) // start with buffered channel of len(val)
	for _, v := range val {         // push all val objects into the channel
		ch <- v
	}

	// close off the channel to indicate no further values will be written to it
	close(ch)

	return ch
}
