package tunnel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/pzverkov/quantum-go/internal/constants"
	"github.com/pzverkov/quantum-go/pkg/protocol"
)

// mockReadWriter for injecting errors
type mockReadWriter struct {
	readError  error
	writeError error
	readData   []byte
	writeData  bytes.Buffer
}

func (m *mockReadWriter) Read(p []byte) (n int, err error) {
	if m.readError != nil {
		return 0, m.readError
	}
	if len(m.readData) == 0 {
		return 0, io.EOF
	}
	n = copy(p, m.readData)
	m.readData = m.readData[n:]
	return n, nil
}

func (m *mockReadWriter) Write(p []byte) (n int, err error) {
	if m.writeError != nil {
		return 0, m.writeError
	}
	return m.writeData.Write(p)
}

func TestHandshakeInvalidMessages(t *testing.T) {
	session, _ := NewSession(RoleInitiator)
	h := NewHandshake(session)

	// Test ProcessServerHello with wrong message type
	invalidMsg := []byte{0xFF, 0, 0, 0, 0}
	err := h.ProcessServerHello(invalidMsg)
	if err == nil {
		t.Error("expected error for invalid message type in ProcessServerHello")
	}

	// Test ProcessServerFinished with wrong message type
	err = h.ProcessServerFinished(invalidMsg)
	if err == nil {
		t.Error("expected error for invalid message type in ProcessServerFinished")
	}
}

func TestHandshakeStateTransitions(t *testing.T) {
	session, _ := NewSession(RoleInitiator)
	h := NewHandshake(session)

	if h.State() != HandshakeStateInitial {
		t.Errorf("expected Initial state, got %v", h.State())
	}

	if h.IsComplete() {
		t.Error("handshake should not be complete initially")
	}
}

func TestHandshakeErrorPaths(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	session, _ := NewSession(RoleInitiator)

	// Test InitiatorHandshake with closed connection
	_ = clientConn.Close()
	err := InitiatorHandshake(session, clientConn)
	if err == nil {
		t.Error("expected error for handshake on closed connection")
	}

	session2, _ := NewSession(RoleResponder)
	err = ResponderHandshake(session2, serverConn)
	if err == nil {
		t.Error("expected error for handshake on closed connection (responder)")
	}
}

func TestHandshakeResumptionErrorPaths(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	session, _ := NewSession(RoleInitiator)

	// Test HandshakeResumptionErrorPaths with closed connection
	_ = clientConn.Close()
	err := InitiatorResumptionHandshake(session, clientConn, []byte("ticket"), []byte("secret"))
	if err == nil {
		t.Error("expected error for resumption handshake on closed connection")
	}

	session2, _ := NewSession(RoleResponder)
	err = ResponderResumptionHandshake(session2, serverConn, nil)
	if err == nil {
		t.Error("expected error for resumption handshake on closed connection (responder)")
	}
}

func TestHandshakeSelectCipherSuite(t *testing.T) {
	// No common cipher suite
	offered := []constants.CipherSuite{constants.CipherSuite(0xFF)}

	suite := selectCipherSuite(offered)
	if suite != 0 {
		t.Errorf("expected 0 (no match), got %v", suite)
	}
}

func TestHandshakeDeriveKeysError(t *testing.T) {
	session, _ := NewSession(RoleInitiator)
	h := NewHandshake(session)

	// Try to derive keys before shared secret is set
	err := h.deriveHandshakeKeys()
	if err == nil {
		t.Error("expected error when deriving keys without shared secret")
	}
}

func TestHandshakeVersionMismatch(t *testing.T) {
	session, _ := NewSession(RoleResponder)
	h := NewHandshake(session)

	clientHello := &protocol.ClientHello{
		Version:        protocol.Version{Major: 99, Minor: 99}, // Unsupported version
		Random:         make([]byte, 32),
		CHKEMPublicKey: make([]byte, constants.CHKEMPublicKeySize),
		CipherSuites:   []constants.CipherSuite{constants.CipherSuiteAES256GCM},
	}
	encoded, _ := h.codec.EncodeClientHello(clientHello)

	err := h.ProcessClientHello(encoded)
	if err == nil {
		t.Error("expected error for unsupported version in ProcessClientHello")
	}
}

func TestHandshakeCipherSuiteMismatchInHello(t *testing.T) {
	session, _ := NewSession(RoleResponder)
	h := NewHandshake(session)

	clientHello := &protocol.ClientHello{
		Version:        protocol.Current,
		Random:         make([]byte, 32),
		CHKEMPublicKey: make([]byte, constants.CHKEMPublicKeySize),
		CipherSuites:   []constants.CipherSuite{constants.CipherSuite(0xFF)}, // Unsupported
	}
	encoded, _ := h.codec.EncodeClientHello(clientHello)

	err := h.ProcessClientHello(encoded)
	if err == nil {
		t.Error("expected error for unsupported cipher suite in ProcessClientHello")
	}
}

func TestHandshakeInvalidState(t *testing.T) {
	session, _ := NewSession(RoleInitiator)
	h := NewHandshake(session)

	// Try to CreateClientHello when not in Initial state
	h.state = HandshakeStateComplete
	_, err := h.CreateClientHello()
	if err == nil {
		t.Error("expected error for CreateClientHello in wrong state")
	}

	// Try to ProcessServerHello when not in ClientHelloSent state
	h.state = HandshakeStateInitial
	err = h.ProcessServerHello([]byte("dummy"))
	if err == nil {
		t.Error("expected error for ProcessServerHello in wrong state")
	}

	// Try to CreateClientFinished when not ready
	h.sendCipher = nil
	_, err = h.CreateClientFinished()
	if err == nil {
		t.Error("expected error for CreateClientFinished when cipher not set")
	}
}

func TestHandshakeAuthenticationFailure(t *testing.T) {
	// Mock established sessions to get to Finished state
	clientS, _ := NewSession(RoleInitiator)

	masterSecret := make([]byte, constants.CHKEMSharedSecretSize)
	clientS.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

	clientH := NewHandshake(clientS)
	clientH.state = HandshakeStateClientFinishedSent

	// Mock ciphers for handshake
	clientH.recvCipher = clientS.recvCipher // Just for testing decryption failure

	// Test ProcessServerFinished with invalid ciphertext
	invalidCiphertext := make([]byte, 64)
	err := clientH.ProcessServerFinished(invalidCiphertext)
	if err == nil {
		t.Error("expected error for ProcessServerFinished with invalid ciphertext")
	}
}

func TestHandshakeIOErrors(t *testing.T) {
	session, _ := NewSession(RoleInitiator)
	rw := &mockReadWriter{writeError: errors.New("write error")}

	// Test InitiatorHandshake write error on ClientHello
	err := InitiatorHandshake(session, rw)
	if err == nil {
		t.Error("expected error for InitiatorHandshake with write error")
	}

	// Test ResponderHandshake read error on ClientHello
	rw.writeError = nil
	rw.readError = errors.New("read error")
	err = ResponderHandshake(session, rw)
	if err == nil {
		t.Error("expected error for ResponderHandshake with read error")
	}
}

func TestWriteEncryptedRecordError(t *testing.T) {
	rw := &mockReadWriter{writeError: errors.New("write error")}
	err := writeEncryptedRecord(rw, []byte("test"))
	if err == nil {
		t.Error("expected error for writeEncryptedRecord with write error")
	}
}

func TestReadEncryptedRecordError(t *testing.T) {
	// Too short for length prefix
	rw := &mockReadWriter{readData: []byte{0, 0, 0}}
	_, err := readEncryptedRecord(rw)
	if err == nil {
		t.Error("expected error for readEncryptedRecord with short data")
	}

	// Too large length
	rw.readData = []byte{0xFF, 0xFF, 0xFF, 0xFF}
	_, err = readEncryptedRecord(rw)
	if err == nil {
		t.Error("expected error for readEncryptedRecord with too large length")
	}

	// Short data for payload
	rw.readData = []byte{0, 0, 0, 10}
	_, err = readEncryptedRecord(rw)
	if err == nil {
		t.Error("expected error for readEncryptedRecord with short payload")
	}
}
func TestHandshakeAlerts(t *testing.T) {
	session, _ := NewSession(RoleResponder)
	rw := &mockReadWriter{}
	codec := protocol.NewCodec()

	// Manually construct ClientHello with unsupported version to bypass EncodeClientHello validation
	payloadSize := 2 + 32 + 1 + 32 + constants.CHKEMPublicKeySize + 2
	encoded := make([]byte, protocol.HeaderSize+payloadSize)
	encoded[0] = byte(protocol.MessageTypeClientHello)
	binary.BigEndian.PutUint32(encoded[1:5], uint32(payloadSize))
	encoded[5] = 99 // Major version
	encoded[6] = 99 // Minor version
	rw.readData = encoded

	err := ResponderHandshake(session, rw)
	t.Logf("ResponderHandshake error: %v", err)
	if err == nil {
		t.Fatal("expected error for version mismatch")
	}

	t.Logf("WriteData len: %d", rw.writeData.Len())

	// Verify alert was written
	alertData := rw.writeData.Bytes()
	if len(alertData) < protocol.HeaderSize {
		t.Fatal("no alert written to connection")
	}

	msgType, _ := codec.GetMessageType(alertData)
	if msgType != protocol.MessageTypeAlert {
		t.Errorf("expected Alert message, got %v", msgType)
	}

	level, code, _, _ := codec.DecodeAlert(alertData)
	if level != protocol.AlertLevelFatal {
		t.Errorf("expected Fatal alert level, got %v", level)
	}
	if code != protocol.AlertCodeHandshakeFailure {
		t.Errorf("expected HandshakeFailure code, got %v", code)
	}
}
