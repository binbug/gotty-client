//go:build !windows
// +build !windows

package gottyclient

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/signal"
	"syscall"
)

func notifySignalSIGWINCH(c chan<- os.Signal) {
	signal.Notify(c, syscall.SIGWINCH)
}

func resetSignalSIGWINCH() {
	signal.Reset(syscall.SIGWINCH)
}

func getWindowSize() (*WindowSize, error) {
	ws, err := unix.IoctlGetWinsize(0, unix.TIOCGWINSZ)
	if err != nil {
		return nil, fmt.Errorf("ioctl error: %v", err)
	}
	return &WindowSize{Rows: ws.Row, Columns: ws.Col}, nil
}
