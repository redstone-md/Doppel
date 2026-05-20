package mitm

import (
	"errors"
	"io"
	"net"
	"strings"
)

func isClientAbort(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	message := strings.ToLower(err.Error())
	clientAbortFragments := []string{
		"wsasend",
		"connection was aborted",
		"connection reset by peer",
		"broken pipe",
		"use of closed network connection",
	}
	for _, fragment := range clientAbortFragments {
		if strings.Contains(message, fragment) {
			return true
		}
	}
	return false
}
