package gottyclient

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/console"
	"github.com/creack/goselect"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

// message types for gotty
const (
	OutputV1         = '0'
	PongV1           = '1'
	SetWindowTitleV1 = '2'
	SetPreferencesV1 = '3'
	SetReconnectV1   = '4'

	InputV1          = '0'
	PingV1           = '1'
	ResizeTerminalV1 = '2'
)

// message types for gotty v2.0
const (
	// Unknown message type, maybe set by a bug
	UnknownOutput = '0'
	// Normal output to the terminal
	Output = '1'
	// Pong to the browser
	Pong = '2'
	// Set window title of the terminal
	SetWindowTitle = '3'
	// Set terminal preference
	SetPreferences = '4'
	// Make terminal to reconnect
	SetReconnect = '5'

	// Unknown message type, maybe sent by a bug
	UnknownInput = '0'
	// User input typically from a keyboard
	Input = '1'
	// Ping to the server
	Ping = '2'
	// Notify that the browser size has been changed
	ResizeTerminal = '3'
)

type gottyMessageType struct {
	output         byte
	pong           byte
	setWindowTitle byte
	setPreferences byte
	setReconnect   byte
	input          byte
	ping           byte
	resizeTerminal byte
}

// GetAuthTokenURL transforms a GoTTY http URL to its AuthToken file URL
func GetAuthTokenURL(httpURL string) (*url.URL, *http.Header, error) {
	header := http.Header{}
	target, err := url.Parse(httpURL)
	if err != nil {
		return nil, nil, err
	}

	target.Path = strings.TrimLeft(target.Path+"auth_token.js", "/")

	user, err := url.PathUnescape(target.User.String())
	if err != nil {
		user = target.User.String()
	}
	if target.User != nil {
		header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user)))
		target.User = nil
	}

	return target, &header, nil
}

// GetURLQuery returns url.query
func GetURLQuery(rawURL string) (url.Values, error) {
	target, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	return target.Query(), nil
}

// GetWebsocketURL transforms a GoTTY http URL to its WebSocket URL
func GetWebsocketURL(httpURL string) (*url.URL, *http.Header, error) {
	header := http.Header{}
	target, err := url.Parse(httpURL)
	if err != nil {
		return nil, nil, err
	}

	if target.Scheme == "https" {
		target.Scheme = "wss"
	} else {
		target.Scheme = "ws"
	}

	target.Path = strings.TrimLeft(target.Path+"ws", "/")

	user, err := url.PathUnescape(target.User.String())
	if err != nil {
		user = target.User.String()
	}
	if target.User != nil {
		header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user)))
		target.User = nil
	}

	return target, &header, nil
}

type Client struct {
	Dialer          *websocket.Dialer
	Conn            *websocket.Conn
	URL             string
	WriteMutex      *sync.Mutex
	Output          io.Writer
	poison          chan bool
	SkipAuth        bool
	SkipTLSVerify   bool
	UseProxyFromEnv bool
	Connected       bool
	EscapeKeys      []byte
	V2              bool
	Cookie          string
	WSOrigin        string
	WSUrl           string
	User            string
	Password        string
	MessageProtocol MessageProtocol
}

type querySingleType struct {
	AuthToken string `json:"AuthToken"`
	Arguments string `json:"Arguments"`
}

func (c *Client) write(data []byte) error {
	if data == nil {
		return nil
	}
	c.WriteMutex.Lock()
	defer c.WriteMutex.Unlock()
	return c.Conn.WriteMessage(websocket.TextMessage, data)
}

// GetAuthToken retrieves an Auth Token from dynamic auth_token.js file
func (c *Client) GetAuthToken() (string, error) {
	if !c.SkipAuth {
		return "", nil
	}
	target, header, err := GetAuthTokenURL(c.URL)
	if err != nil {
		return "", err
	}
	if c.User != "" {
		basicAuth := c.User + ":" + c.Password
		header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(basicAuth)))
	}

	logrus.Debugf("Fetching auth token auth-token: %q", target.String())
	req, err := http.NewRequest("GET", target.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = *header
	tr := &http.Transport{}
	if c.SkipTLSVerify {
		conf := &tls.Config{InsecureSkipVerify: true}
		tr.TLSClientConfig = conf
	}
	if c.UseProxyFromEnv {
		tr.Proxy = http.ProxyFromEnvironment
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	switch resp.StatusCode {
	case 200:
		// Everything is OK
	default:
		return "", fmt.Errorf("unknown status code: %d (%s)", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile("var gotty_auth_token = '(.*)'")
	output := re.FindStringSubmatch(string(body))
	if len(output) == 0 {
		return "", fmt.Errorf("cannot fetch GoTTY auth-token, please upgrade your GoTTY server")
	}

	return output[1], nil
}

// Connect tries to dial a websocket server
func (c *Client) Connect() error {
	// Retrieve AuthToken
	authToken := ""
	if !c.SkipAuth {
		a, err := c.GetAuthToken()
		if err != nil {
			return err
		}
		authToken = a
		logrus.Debugf("Auth-token: %q", authToken)
	}

	// Open WebSocket connection
	target, header, err := GetWebsocketURL(c.URL)
	if err != nil {
		return err
	}

	if c.WSUrl != "" {
		target, err = url.Parse(c.WSUrl)
		if err != nil {
			return err
		}
	}

	if c.User != "" {
		basicAuth := c.User + ":" + c.Password
		header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(basicAuth)))
	}
	if c.WSOrigin != "" {
		header.Add("Origin", c.WSOrigin)
	}

	if c.Cookie != "" {
		header.Add("Cookie", c.Cookie)
	}

	if c.MessageProtocol == nil {
		c.MessageProtocol = &DefaultMessageProtocol{}
	}

	c.MessageProtocol.Init(c)

	logrus.Debugf("Connecting to websocket: %q", target.String())
	if c.SkipTLSVerify {
		c.Dialer.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if c.UseProxyFromEnv {
		c.Dialer.Proxy = http.ProxyFromEnvironment
	}
	conn, _, err := c.Dialer.Dial(target.String(), *header)
	if err != nil {
		return err
	}
	c.Conn = conn
	c.Connected = true

	connectData, err := c.MessageProtocol.Connect(c.URL)
	if err != nil {
		return err
	}

	if connectData != nil {
		err = c.write(connectData)
		if err != nil {
			return err
		}
	}

	go c.pingLoop()

	return nil
}

func (c *Client) pingLoop() {
	for {
		logrus.Debugf("Sending ping")
		err := c.write(c.MessageProtocol.Ping())
		if err != nil {
			logrus.Warnf("c.write: %v", err)
		}
		time.Sleep(30 * time.Second)
	}
}

// Close will nicely close the dialer
func (c *Client) Close() error {
	return c.Conn.Close()
}

// ExitLoop will kill all goroutines launched by c.Loop()
// ExitLoop() -> wait Loop() -> Close()
func (c *Client) ExitLoop() {
	fname := "ExitLoop"
	openPoison(fname, c.poison)
}

// Loop will look indefinitely for new messages
func (c *Client) Loop() error {

	if !c.Connected {
		err := c.Connect()
		if err != nil {
			return err
		}
	}
	term, err := console.ConsoleFromFile(os.Stdout)
	if err != nil {
		return fmt.Errorf("os.Stdout is not a valid terminal")
	}
	err = term.SetRaw()
	if err != nil {
		return fmt.Errorf("error setting raw terminal: %v", err)
	}
	defer func() {
		_ = term.Reset()
	}()

	wg := &sync.WaitGroup{}

	wg.Add(1)
	go c.termsizeLoop(wg)

	wg.Add(1)
	go c.readLoop(wg)

	wg.Add(1)
	go c.writeLoop(wg)

	/* Wait for all of the above goroutines to finish */
	wg.Wait()

	logrus.Debug("Client.Loop() exiting")
	return nil
}

type WindowSize struct {
	Rows    uint16 `json:"rows"`
	Columns uint16 `json:"columns"`
}

type poisonReason int

const (
	committedSuicide = iota
	killed
)

func openPoison(fname string, poison chan bool) poisonReason {
	logrus.Debug(fname + " suicide")

	/*
	 * The close() may raise panic if multiple goroutines commit suicide at the
	 * same time. Prevent that panic from bubbling up.
	 */
	defer func() {
		if r := recover(); r != nil {
			logrus.Debug("Prevented panic() of simultaneous suicides", r)
		}
	}()

	/* Signal others to die */
	close(poison)
	return committedSuicide
}

func die(fname string, poison chan bool) poisonReason {
	logrus.Debug(fname + " died")

	wasOpen := <-poison
	if wasOpen {
		logrus.Error("ERROR: The channel was open when it wasn't supposed to be")
	}

	return killed
}

func (c *Client) termsizeLoop(wg *sync.WaitGroup) poisonReason {
	defer wg.Done()
	fname := "termsizeLoop"

	ch := make(chan os.Signal, 1)
	notifySignalSIGWINCH(ch)
	defer resetSignalSIGWINCH()

	for {
		if tws, err := getWindowSize(); err != nil {
			logrus.Warn(err)
		} else {
			data, err := c.MessageProtocol.WinSizeChange(tws)
			if err != nil {
				logrus.Warn(err)
			} else {
				if err = c.write(data); err != nil {
					logrus.Warnf("ws.WriteMessage failed: %v", err)
				}
			}
		}

		select {
		case <-c.poison:
			/* Somebody poisoned the well; die */
			return die(fname, c.poison)
		case <-ch:
		}
	}
}

type exposeFd interface {
	Fd() uintptr
}

func (c *Client) writeLoop(wg *sync.WaitGroup) poisonReason {
	defer wg.Done()
	fname := "writeLoop"

	buff := make([]byte, 128)

	rdfs := &goselect.FDSet{}
	reader := io.ReadCloser(os.Stdin)

	pr := NewEscapeProxy(reader, c.EscapeKeys)
	defer reader.Close()

	for {
		select {
		case <-c.poison:
			/* Somebody poisoned the well; die */
			return die(fname, c.poison)
		default:
		}

		rdfs.Zero()
		rdfs.Set(reader.(exposeFd).Fd())
		err := goselect.RetrySelect(1, rdfs, nil, nil, 50*time.Millisecond, 3, 50*time.Millisecond)
		if err != nil && err != syscall.EINTR {
			logrus.Debugf(err.Error())
			return openPoison(fname, c.poison)
		}
		if rdfs.IsSet(reader.(exposeFd).Fd()) {
			size, err := pr.Read(buff)

			if err != nil {
				if err == io.EOF {
					// Send EOF to GoTTY

					// Send 'Input' marker, as defined in GoTTY::client_context.go,
					// followed by EOT (a translation of Ctrl-D for terminals)
					err = c.write(c.MessageProtocol.EOF())

					if err != nil {
						return openPoison(fname, c.poison)
					}
					continue
				} else {
					return openPoison(fname, c.poison)
				}
			}

			if size <= 0 {
				continue
			}

			data := buff[:size]
			err = c.write(c.MessageProtocol.Input(data))
			if err != nil {
				return openPoison(fname, c.poison)
			}
		}
	}

}

func (c *Client) readLoop(wg *sync.WaitGroup) poisonReason {
	defer wg.Done()
	fname := "readLoop"

	type MessageNonBlocking struct {
		Data []byte
		Err  error
	}
	msgChan := make(chan MessageNonBlocking)

	for {
		go func() {
			_, data, err := c.Conn.ReadMessage()
			msgChan <- MessageNonBlocking{Data: data, Err: err}
		}()

		select {
		case <-c.poison:
			/* Somebody poisoned the well; die */
			return die(fname, c.poison)
		case msg := <-msgChan:
			if msg.Err != nil {

				if _, ok := msg.Err.(*websocket.CloseError); !ok {
					logrus.Warnf("c.Conn.ReadMessage: %v", msg.Err)
				}
				return openPoison(fname, c.poison)
			}

			c.MessageProtocol.Output(msg.Data, c.Output)
		}
	}
}

// SetOutput changes the output stream
func (c *Client) SetOutput(w io.Writer) {
	c.Output = w
}

// ParseURL parses an URL which may be incomplete and tries to standardize it
func ParseURL(input string) (string, error) {
	parsed, err := url.Parse(input)
	if err != nil {
		return "", err
	}
	switch parsed.Scheme {
	case "http", "https":
		// everything is ok
	default:
		return ParseURL(fmt.Sprintf("http://%s", input))
	}
	return parsed.String(), nil
}

// NewClient returns a GoTTY client object
func NewClient(inputURL string) (*Client, error) {
	parsedURL, err := ParseURL(inputURL)
	if err != nil {
		return nil, err
	}
	return &Client{
		Dialer:     &websocket.Dialer{},
		URL:        parsedURL,
		WriteMutex: &sync.Mutex{},
		Output:     os.Stdout,
		poison:     make(chan bool),
	}, nil
}
