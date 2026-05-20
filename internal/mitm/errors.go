package mitm

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
)

var errConnectionTakenOver = errors.New("connection taken over")

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

func isConnectionTakenOver(err error) bool {
	return errors.Is(err, errConnectionTakenOver) || errors.Is(err, context.Canceled)
}
