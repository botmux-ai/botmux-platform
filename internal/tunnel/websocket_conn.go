package tunnel

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WebSocketConn presents a WebSocket carrying binary messages as a continuous
// net.Conn byte stream. The daemon deliberately sends raw HTTP bytes in binary
// frames; frame boundaries are not meaningful to the HTTP transport.
type WebSocketConn struct {
	ws      *websocket.Conn
	readMu  sync.Mutex
	writeMu sync.Mutex
	reader  io.Reader
}

func NewWebSocketConn(ws *websocket.Conn) *WebSocketConn { return &WebSocketConn{ws: ws} }

// Read returns io.EOF once the peer closes the WebSocket, whatever the close
// code: like Node's createWebSocketStream, which ends the duplex on 'close'.
// Truncation is then decided by the HTTP framing above (a chunked or
// Content-Length body cut short is an unexpected EOF and aborts the browser),
// while a close-delimited response body ends normally.
func (c *WebSocketConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	for {
		if c.reader != nil {
			n, err := c.reader.Read(p)
			if err == nil || (n > 0 && errors.Is(err, io.EOF)) {
				return n, nil
			}
			if !errors.Is(err, io.EOF) {
				return n, endOfStream(err)
			}
			c.reader = nil
		}
		kind, reader, err := c.ws.NextReader()
		if err != nil {
			return 0, endOfStream(err)
		}
		if kind != websocket.BinaryMessage && kind != websocket.TextMessage {
			continue
		}
		c.reader = reader
	}
}

func (c *WebSocketConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	w, err := c.ws.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}
	n, writeErr := w.Write(p)
	closeErr := w.Close()
	if writeErr != nil {
		return n, writeErr
	}
	return n, closeErr
}

func (c *WebSocketConn) Close() error                       { return c.ws.Close() }
func (c *WebSocketConn) LocalAddr() net.Addr                { return c.ws.UnderlyingConn().LocalAddr() }
func (c *WebSocketConn) RemoteAddr() net.Addr               { return c.ws.UnderlyingConn().RemoteAddr() }
func (c *WebSocketConn) SetDeadline(t time.Time) error      { return c.ws.UnderlyingConn().SetDeadline(t) }
func (c *WebSocketConn) SetReadDeadline(t time.Time) error  { return c.ws.SetReadDeadline(t) }
func (c *WebSocketConn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }

func endOfStream(err error) error {
	var closeErr *websocket.CloseError
	if errors.As(err, &closeErr) {
		return io.EOF
	}
	return err
}
