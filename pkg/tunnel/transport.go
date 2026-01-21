// transport.go implements the encrypted data transport layer.
//
// The transport layer provides:
//   - Encrypted and authenticated data transmission
//   - Sequence number management for replay protection
//   - Automatic fragmentation for large payloads
//   - Keepalive/ping-pong mechanism
//   - Graceful close notification
package tunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/pzverkov/quantum-go/internal/constants"
	qerrors "github.com/pzverkov/quantum-go/internal/errors"
	"github.com/pzverkov/quantum-go/pkg/protocol"
)

// Transport provides encrypted communication over an established session.
type Transport struct {
	session *Session
	conn    net.Conn
	codec   *protocol.Codec

	// Timeouts
	readTimeout  time.Duration
	writeTimeout time.Duration

	// Mutex for write operations
	writeMu sync.Mutex

	// Close state
	closed   bool
	closedMu sync.RWMutex
}

// TransportConfig holds configuration for the transport layer.
type TransportConfig struct {
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	RateLimit    RateLimitConfig
	// Observer is a shared observer for all sessions (ignored if ObserverFactory is set).
	Observer Observer

	// ObserverFactory builds a per-session observer (takes precedence over Observer).
	ObserverFactory ObserverFactory
}

// RateLimitConfig holds configuration for rate limiting.
type RateLimitConfig struct {
	// MaxConnectionsPerIP is the maximum number of concurrent connections allowed from a single IP.
	// 0 means no limit.
	MaxConnectionsPerIP int

	// HandshakeRateLimit is the maximum number of handshakes per second allowed globally.
	// 0 means no limit.
	HandshakeRateLimit float64

	// HandshakeBurst is the maximum burst of handshakes allowed.
	// If 0, defaults to 1 when HandshakeRateLimit is set.
	HandshakeBurst int
}

// DefaultTransportConfig returns sensible defaults.
func DefaultTransportConfig() TransportConfig {
	return TransportConfig{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
}

// NewTransport creates a new transport over an established session.
func NewTransport(session *Session, conn net.Conn, config TransportConfig) (*Transport, error) {
	if session.State() != SessionStateEstablished {
		return nil, qerrors.ErrInvalidState
	}

	if session.observer == nil {
		if observer := observerFromConfig(config, session); observer != nil {
			session.SetObserver(observer)
		}
	}

	return &Transport{
		session:      session,
		conn:         conn,
		codec:        protocol.NewCodec(),
		readTimeout:  config.ReadTimeout,
		writeTimeout: config.WriteTimeout,
	}, nil
}

// Send encrypts and sends data over the tunnel.
func (t *Transport) Send(data []byte) error {
	t.closedMu.RLock()
	if t.closed {
		t.closedMu.RUnlock()
		return qerrors.ErrTunnelClosed
	}
	t.closedMu.RUnlock()

	if len(data) > constants.MaxPayloadSize {
		return qerrors.ErrMessageTooLarge
	}

	// Encrypt data
	ciphertext, seq, err := t.session.Encrypt(data)
	if err != nil {
		return err
	}

	// Encode as data message
	msg, err := t.codec.EncodeData(seq, ciphertext)
	if err != nil {
		t.recordProtocolError(err)
		return err
	}

	// Send with timeout
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	if t.writeTimeout > 0 {
		_ = t.conn.SetWriteDeadline(time.Now().Add(t.writeTimeout))
	}

	_, err = t.conn.Write(msg)
	if err != nil {
		return err
	}

	// Check if rekey is needed and initiate if so
	if err := t.CheckAndRekey(); err != nil {
		// Log but don't fail the send - rekey errors are non-fatal
		_ = err
	}

	return nil
}

// Receive reads and decrypts data from the tunnel.
func (t *Transport) Receive() ([]byte, error) {
	t.closedMu.RLock()
	if t.closed {
		t.closedMu.RUnlock()
		return nil, qerrors.ErrTunnelClosed
	}
	t.closedMu.RUnlock()

	// Read with timeout
	if t.readTimeout > 0 {
		_ = t.conn.SetReadDeadline(time.Now().Add(t.readTimeout))
	}

	// Read message
	msg, err := t.codec.ReadMessage(t.conn)
	if err != nil {
		if err == io.EOF {
			return nil, qerrors.ErrTunnelClosed
		}
		t.recordProtocolError(err)
		return nil, err
	}

	// Get message type
	msgType, err := t.codec.GetMessageType(msg)
	if err != nil {
		t.recordProtocolError(err)
		return nil, err
	}

	switch msgType {
	case protocol.MessageTypeData:
		data, err := t.handleData(msg)
		if err != nil {
			t.recordProtocolError(err)
		}
		return data, err

	case protocol.MessageTypePing:
		// Respond with pong
		if err := t.sendPong(); err != nil {
			return nil, err
		}
		// Continue reading
		return t.Receive()

	case protocol.MessageTypePong:
		// Keepalive response, continue reading
		return t.Receive()

	case protocol.MessageTypeClose:
		t.closedMu.Lock()
		t.closed = true
		t.closedMu.Unlock()
		return nil, qerrors.ErrTunnelClosed

	case protocol.MessageTypeRekey:
		// Handle incoming rekey request/response
		if err := t.handleRekey(msg); err != nil {
			t.recordProtocolError(err)
			return nil, err
		}
		// Continue reading after processing rekey
		return t.Receive()

	case protocol.MessageTypeAlert:
		level, code, desc, _ := t.codec.DecodeAlert(msg)
		if code == protocol.AlertCodeCloseNotify {
			t.closedMu.Lock()
			t.closed = true
			t.closedMu.Unlock()
			return nil, qerrors.ErrTunnelClosed
		}
		err := qerrors.NewProtocolError("alert", &alertError{level: level, code: code, desc: desc})
		t.recordProtocolError(err)
		return nil, err

	default:
		t.recordProtocolError(qerrors.ErrInvalidMessage)
		return nil, qerrors.ErrInvalidMessage
	}
}

// handleData processes an encrypted data message.
func (t *Transport) handleData(msg []byte) ([]byte, error) {
	// Decode data message
	seq, ciphertext, err := t.codec.DecodeData(msg)
	if err != nil {
		return nil, err
	}

	// Check if we've reached the activation sequence for pending keys
	if t.session.IsRekeyInProgress() && seq >= t.session.GetRekeyActivationSeq() {
		t.session.ActivatePendingKeys()
	}

	// Decrypt
	plaintext, err := t.session.Decrypt(ciphertext, seq)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// SendPing sends a keepalive ping.
func (t *Transport) SendPing() error {
	t.closedMu.RLock()
	if t.closed {
		t.closedMu.RUnlock()
		return qerrors.ErrTunnelClosed
	}
	t.closedMu.RUnlock()

	msg := t.encodePing()

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	if t.writeTimeout > 0 {
		_ = t.conn.SetWriteDeadline(time.Now().Add(t.writeTimeout))
	}

	_, err := t.conn.Write(msg)
	return err
}

// sendPong sends a keepalive pong response.
func (t *Transport) sendPong() error {
	msg := t.encodePong()

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	if t.writeTimeout > 0 {
		_ = t.conn.SetWriteDeadline(time.Now().Add(t.writeTimeout))
	}

	_, err := t.conn.Write(msg)
	return err
}

// encodePing creates a ping message.
func (t *Transport) encodePing() []byte {
	buf := make([]byte, protocol.HeaderSize)
	buf[0] = byte(protocol.MessageTypePing)
	binary.BigEndian.PutUint32(buf[1:], 0)
	return buf
}

// encodePong creates a pong message.
func (t *Transport) encodePong() []byte {
	buf := make([]byte, protocol.HeaderSize)
	buf[0] = byte(protocol.MessageTypePong)
	binary.BigEndian.PutUint32(buf[1:], 0)
	return buf
}

// sendAlert sends an alert message to the peer.
func (t *Transport) sendAlert(level protocol.AlertLevel, code protocol.AlertCode, desc string) error {
	msg := t.codec.EncodeAlert(level, code, desc)

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	// Use a short timeout for alerts
	_ = t.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := t.conn.Write(msg)
	return err
}

// Close gracefully closes the transport.
func (t *Transport) Close() error {
	t.closedMu.Lock()
	if t.closed {
		t.closedMu.Unlock()
		return nil
	}
	t.closed = true
	t.closedMu.Unlock()

	// Send close notification alert with short timeout (best effort)
	t.closedMu.RLock()
	isEstablished := t.session.State() == SessionStateEstablished
	t.closedMu.RUnlock()

	if isEstablished {
		// Use a very short timeout for close notification to avoid blocking
		_ = t.conn.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
		msg := t.codec.EncodeAlert(protocol.AlertLevelWarning, protocol.AlertCodeCloseNotify, "connection closed")
		t.writeMu.Lock()
		_, _ = t.conn.Write(msg)
		t.writeMu.Unlock()
	}

	// Close session
	t.session.Close()
	if t.session.observer != nil {
		t.session.observer.OnSessionEnd()
	}

	// Close the underlying connection
	_ = t.conn.Close()

	return nil
}

// --- Rekey Protocol Methods ---

// handleRekey processes an incoming rekey message.
func (t *Transport) handleRekey(msg []byte) error {
	newPublicKey, activationSeq, err := t.codec.DecodeRekey(msg)
	if err != nil {
		return err
	}

	// If we're the responder and receive a rekey request
	if t.session.Role == RoleResponder && !t.session.IsRekeyInProgress() {
		// Prepare response (encapsulate to new key)
		ciphertext, err := t.session.PrepareRekeyResponse(newPublicKey, activationSeq)
		if err != nil {
			return err
		}

		// Send rekey response back
		return t.sendRekeyResponse(ciphertext, activationSeq)
	}

	// If we're the initiator and receive a rekey response (ciphertext)
	if t.session.Role == RoleInitiator && t.session.IsRekeyInProgress() {
		// Process the response
		if err := t.session.ProcessRekeyResponse(newPublicKey); err != nil {
			return err
		}
	}

	return nil
}

// SendRekey initiates a rekey operation (called by initiator).
func (t *Transport) SendRekey() error {
	t.closedMu.RLock()
	if t.closed {
		t.closedMu.RUnlock()
		return qerrors.ErrTunnelClosed
	}
	t.closedMu.RUnlock()

	observer := t.session.observer
	var done func(error)
	if observer != nil && t.session.Role == RoleInitiator {
		_, done = observer.OnRekeyStart(context.Background())
	}

	err := func() error {
		// Initiate rekey in session
		newPublicKey, activationSeq, err := t.session.InitiateRekey()
		if err != nil {
			return err
		}

		// Encode rekey message
		msg, err := t.codec.EncodeRekey(newPublicKey, activationSeq)
		if err != nil {
			return err
		}

		// Send
		t.writeMu.Lock()
		defer t.writeMu.Unlock()

		if t.writeTimeout > 0 {
			_ = t.conn.SetWriteDeadline(time.Now().Add(t.writeTimeout))
		}

		_, err = t.conn.Write(msg)
		return err
	}()

	if done != nil {
		done(err)
	}

	return err
}

// sendRekeyResponse sends a rekey response (called by responder).
func (t *Transport) sendRekeyResponse(ciphertext []byte, activationSeq uint64) error {
	// For the response, we send the ciphertext in place of public key
	// The format is the same, responder sends ciphertext back
	msg, err := t.codec.EncodeRekey(ciphertext, activationSeq)
	if err != nil {
		return err
	}

	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	if t.writeTimeout > 0 {
		_ = t.conn.SetWriteDeadline(time.Now().Add(t.writeTimeout))
	}

	_, err = t.conn.Write(msg)
	return err
}

// CheckAndRekey checks if rekey is needed and initiates it if so.
// Should be called periodically or after Send operations.
func (t *Transport) CheckAndRekey() error {
	if t.session.Role != RoleInitiator {
		return nil // Only initiator triggers rekey
	}

	if t.session.IsRekeyInProgress() {
		return nil // Already rekeying
	}

	if t.session.NeedsRekey() {
		return t.SendRekey()
	}

	return nil
}

// Session returns the underlying session.
func (t *Transport) Session() *Session {
	return t.session
}

// LocalAddr returns the local network address.
func (t *Transport) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (t *Transport) RemoteAddr() net.Addr {
	return t.conn.RemoteAddr()
}

// SetReadTimeout sets the read timeout.
func (t *Transport) SetReadTimeout(d time.Duration) {
	t.readTimeout = d
}

// SetWriteTimeout sets the write timeout.
func (t *Transport) SetWriteTimeout(d time.Duration) {
	t.writeTimeout = d
}

func (t *Transport) recordProtocolError(err error) {
	if err == nil {
		return
	}
	if t.session.observer != nil && isProtocolError(err) {
		t.session.observer.OnProtocolError(err)
	}
}

// alertError represents an alert received from the peer.
type alertError struct {
	level protocol.AlertLevel
	code  protocol.AlertCode
	desc  string
}

func (e *alertError) Error() string {
	prefix := "alert (warning): "
	if e.level == protocol.AlertLevelFatal {
		prefix = "alert (fatal): "
	}

	if e.desc != "" {
		return prefix + e.desc
	}
	return fmt.Sprintf("%scode %d", prefix, e.code)
}

// --- Tunnel (Convenience Wrapper) ---

// Tunnel represents a complete CH-KEM VPN tunnel.
type Tunnel struct {
	*Transport
}

// Dial establishes a new tunnel as initiator.
func Dial(network, address string) (*Tunnel, error) {
	return DialWithConfig(network, address, DefaultTransportConfig())
}

// DialWithConfig establishes a new tunnel with custom configuration.
func DialWithConfig(network, address string, config TransportConfig) (*Tunnel, error) {
	// Connect
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}

	// Create session as initiator
	session, err := NewSession(RoleInitiator)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if observer := observerFromConfig(config, session); observer != nil {
		session.SetObserver(observer)
		observer.OnSessionStart()
	}

	// Perform handshake
	if err := InitiatorHandshake(session, conn); err != nil {
		if session.observer != nil {
			session.observer.OnSessionFailed(err)
			session.observer.OnSessionEnd()
		}
		_ = conn.Close()
		return nil, err
	}

	// Create transport
	transport, err := NewTransport(session, conn, config)
	if err != nil {
		if session.observer != nil {
			session.observer.OnSessionFailed(err)
			session.observer.OnSessionEnd()
		}
		_ = conn.Close()
		return nil, err
	}

	return &Tunnel{Transport: transport}, nil
}

// Listen creates a listener for incoming tunnel connections.
func Listen(network, address string) (*Listener, error) {
	ln, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}

	return &Listener{
		listener: ln,
		config:   DefaultTransportConfig(),
	}, nil
}

// Listener accepts incoming tunnel connections.
type Listener struct {
	listener net.Listener
	config   TransportConfig

	ipLimiter        *IPRateLimiter
	handshakeLimiter *HandshakeLimiter
}

// Accept waits for and returns the next tunnel connection.
func (l *Listener) Accept() (*Tunnel, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}

	// Check IP rate limit
	var remoteIP string
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		remoteIP = tcpAddr.IP.String()
	} else {
		host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
		if err == nil {
			remoteIP = host
		} else {
			remoteIP = conn.RemoteAddr().String()
		}
	}

	if l.ipLimiter != nil && !l.ipLimiter.AllowConnection(remoteIP) {
		_ = conn.Close()
		// Return a temporary error so accept loop might continue?
		// Or just return error. For now return error.
		return nil, qerrors.NewProtocolError("rate limit", &alertError{
			level: protocol.AlertLevelFatal,
			code:  protocol.AlertCodeInternalError,
			desc:  "connection rate limit exceeded",
		})
	}

	// Wrap connection to release IP limit on close
	if l.ipLimiter != nil {
		conn = &rateLimitedConn{
			Conn:      conn,
			limiter:   l.ipLimiter,
			ip:        remoteIP,
			closeOnce: sync.Once{},
		}
	}

	// Create session as responder
	session, err := NewSession(RoleResponder)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if observer := observerFromConfig(l.config, session); observer != nil {
		session.SetObserver(observer)
		observer.OnSessionStart()
	}

	// Perform handshake
	// Check handshake rate limit
	if l.handshakeLimiter != nil && !l.handshakeLimiter.AllowHandshake() {
		_ = conn.Close()
		// We don't have a specific error for this, but we can log or just return error
		err := qerrors.NewProtocolError("rate limit", &alertError{
			level: protocol.AlertLevelFatal,
			code:  protocol.AlertCodeInternalError, // Or a custom code if we had one
			desc:  "handshake rate limit exceeded",
		})
		if session.observer != nil {
			session.observer.OnSessionFailed(err)
			session.observer.OnSessionEnd()
		}
		return nil, err
	}

	if err := ResponderHandshake(session, conn); err != nil {
		if session.observer != nil {
			session.observer.OnSessionFailed(err)
			session.observer.OnSessionEnd()
		}
		_ = conn.Close()
		return nil, err
	}

	// Create transport
	transport, err := NewTransport(session, conn, l.config)
	if err != nil {
		if session.observer != nil {
			session.observer.OnSessionFailed(err)
			session.observer.OnSessionEnd()
		}
		_ = conn.Close()
		return nil, err
	}

	return &Tunnel{Transport: transport}, nil
}

// Close closes the listener.
func (l *Listener) Close() error {
	return l.listener.Close()
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

// SetConfig sets the transport configuration for new connections.
func (l *Listener) SetConfig(config TransportConfig) {
	l.config = config
	// Re-initialize limiters based on new config
	if config.RateLimit.MaxConnectionsPerIP > 0 {
		l.ipLimiter = NewIPRateLimiter(config.RateLimit.MaxConnectionsPerIP)
	} else {
		l.ipLimiter = nil
	}

	if config.RateLimit.HandshakeRateLimit > 0 {
		l.handshakeLimiter = NewHandshakeLimiter(config.RateLimit.HandshakeRateLimit, config.RateLimit.HandshakeBurst)
	} else {
		l.handshakeLimiter = nil
	}
}

// rateLimitedConn wraps a net.Conn to release the IP rate limit on close.
type rateLimitedConn struct {
	net.Conn
	limiter   *IPRateLimiter
	ip        string
	closeOnce sync.Once
}

// Close closes the connection and releases the IP rate limit token.
func (c *rateLimitedConn) Close() error {
	err := c.Conn.Close()
	c.closeOnce.Do(func() {
		if c.limiter != nil {
			c.limiter.ReleaseConnection(c.ip)
		}
	})
	return err
}
