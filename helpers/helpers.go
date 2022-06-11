package helpers

import "time"

func currentMillis() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}
