package gottyclient

import "io"

type MessageProtocol interface {
	Init(c *Client)
	Ping() []byte
	Connect(URL string) ([]byte, error)
	WinSizeChange(wsize *WindowSize) ([]byte, error)
	Input(data []byte) []byte
	Output(data []byte, output io.Writer)
	EOF() []byte
}
