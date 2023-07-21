package gottyclient

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
)

type DefaultMessageProtocol struct {
	message *gottyMessageType
}

func (d *DefaultMessageProtocol) Init(c *Client) {
	d.initMessageType(c.V2)
}

func (d *DefaultMessageProtocol) initMessageType(V2 bool) {
	if V2 {
		d.message = &gottyMessageType{
			output:         Output,
			pong:           Pong,
			setWindowTitle: SetWindowTitle,
			setPreferences: SetPreferences,
			setReconnect:   SetReconnect,
			input:          Input,
			ping:           Ping,
			resizeTerminal: ResizeTerminal,
		}
	} else {
		d.message = &gottyMessageType{
			output:         OutputV1,
			pong:           PongV1,
			setWindowTitle: SetWindowTitleV1,
			setPreferences: SetPreferencesV1,
			setReconnect:   SetReconnectV1,
			input:          InputV1,
			ping:           PingV1,
			resizeTerminal: ResizeTerminalV1,
		}
	}
}

func (d *DefaultMessageProtocol) Ping() []byte {
	return []byte{d.message.ping}
}

func (d *DefaultMessageProtocol) Connect(URL string) ([]byte, error) {
	// Pass arguments and auth-token
	query, err := GetURLQuery(URL)
	if err != nil {
		return nil, err
	}
	querySingle := querySingleType{
		Arguments: "?" + query.Encode(),
		AuthToken: "",
	}
	queryJSON, err := json.Marshal(querySingle)
	if err != nil {
		logrus.Errorf("Failed to parse init message %v", err)
		return nil, err
	}
	// Send Json
	logrus.Debugf("Sending arguments and auth-token")
	return queryJSON, nil
}

func (d *DefaultMessageProtocol) WinSizeChange(wsize *WindowSize) ([]byte, error) {
	b, err := json.Marshal(wsize)
	if err != nil {
		return nil, err
	}
	return append([]byte{d.message.resizeTerminal}, b...), nil
}

func (d *DefaultMessageProtocol) Input(data []byte) []byte {
	return append([]byte{d.message.input}, data...)
}

func (d *DefaultMessageProtocol) Output(data []byte, output io.Writer) {
	switch data[0] {
	case d.message.output: // data
		buf, err := base64.StdEncoding.DecodeString(string(data[1:]))
		if err != nil {
			logrus.Warnf("Invalid base64 content: %q", data[1:])
			break
		}
		_, _ = output.Write(buf)
	case d.message.pong: // pong
	case d.message.setWindowTitle: // new title
		newTitle := string(data[1:])
		_, _ = fmt.Fprintf(output, "\033]0;%s\007", newTitle)
	case d.message.setPreferences: // json prefs
		logrus.Debugf("Unhandled protocol message: json pref: %s", string(data[1:]))
	case d.message.setReconnect: // autoreconnect
		logrus.Debugf("Unhandled protocol message: autoreconnect: %s", string(data))
	default:
		logrus.Warnf("Unhandled protocol message: %s", string(data))
	}
}

func (d *DefaultMessageProtocol) EOF() []byte {
	return append([]byte{d.message.input}, byte(4))
}
