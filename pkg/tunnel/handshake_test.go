package tunnel

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/pzverkov/quantum-go/internal/constants"
	"github.com/pzverkov/quantum-go/pkg/crypto"
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
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

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
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

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
	_ = clientS.InitializeKeys(masterSecret, constants.CipherSuiteAES256GCM)

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
	codec := protocol.NewCodec()

	// verifyAlert checks that the written data is a sanitized fatal handshake alert.
	// The description must be generic ("handshake failed") and must NOT contain
	// internal error details like "unsupported version" or "no common cipher suite".
	verifyAlert := func(t *testing.T, alertData []byte, triggerErr error) {
		t.Helper()
		if len(alertData) < protocol.HeaderSize {
			t.Fatal("no alert written to connection")
		}
		msgType, _ := codec.GetMessageType(alertData)
		if msgType != protocol.MessageTypeAlert {
			t.Fatalf("expected Alert message, got %v", msgType)
		}
		level, code, desc, err := codec.DecodeAlert(alertData)
		if err != nil {
			t.Fatalf("failed to decode alert: %v", err)
		}
		if level != protocol.AlertLevelFatal {
			t.Errorf("expected Fatal alert level, got %v", level)
		}
		if code != protocol.AlertCodeHandshakeFailure {
			t.Errorf("expected HandshakeFailure code, got %v", code)
		}
		if desc != "handshake failed" {
			t.Errorf("alert description should be generic, got %q", desc)
		}
		// The internal error text must not appear in the wire message
		if triggerErr != nil && bytes.Contains(alertData, []byte(triggerErr.Error())) {
			t.Errorf("alert wire data contains internal error text: %q", triggerErr.Error())
		}
	}

	t.Run("version mismatch", func(t *testing.T) {
		session, _ := NewSession(RoleResponder)
		rw := &mockReadWriter{}

		payloadSize := 2 + 32 + 1 + 32 + constants.CHKEMPublicKeySize + 2
		encoded := make([]byte, protocol.HeaderSize+payloadSize)
		encoded[0] = byte(protocol.MessageTypeClientHello)
		binary.BigEndian.PutUint32(encoded[1:5], uint32(payloadSize))
		encoded[5] = 99 // Major version
		encoded[6] = 99 // Minor version
		rw.readData = encoded

		err := ResponderHandshake(session, rw)
		if err == nil {
			t.Fatal("expected error for version mismatch")
		}
		verifyAlert(t, rw.writeData.Bytes(), err)
	})

	t.Run("cipher suite mismatch", func(t *testing.T) {
		session, _ := NewSession(RoleResponder)
		rw := &mockReadWriter{}

		// Build raw ClientHello with valid structure but unsupported cipher suite (0xFF).
		// We can't use EncodeClientHello because it validates cipher suites.
		// Layout: Header(5) + Version(2) + Random(32) + SessionIDLen(1) + PubKey(CHKEMPublicKeySize) + CipherCount(2) + CipherSuite(2)
		sessionIDLen := 0
		cipherCount := 1
		payloadSize := 2 + 32 + 1 + sessionIDLen + constants.CHKEMPublicKeySize + 2 + 2*cipherCount
		encoded := make([]byte, protocol.HeaderSize+payloadSize)
		offset := 0
		encoded[offset] = byte(protocol.MessageTypeClientHello)
		offset++
		binary.BigEndian.PutUint32(encoded[offset:], uint32(payloadSize))
		offset += 4
		encoded[offset] = protocol.Current.Major
		encoded[offset+1] = protocol.Current.Minor
		offset += 2
		// Random (32 bytes of zeros is fine for test)
		offset += 32
		// SessionID length = 0
		encoded[offset] = 0
		offset++
		// Public key (zeros)
		offset += constants.CHKEMPublicKeySize
		// Cipher suites: count=1, value=0x00FF (unsupported)
		binary.BigEndian.PutUint16(encoded[offset:], uint16(cipherCount))
		offset += 2
		binary.BigEndian.PutUint16(encoded[offset:], 0x00FF)
		rw.readData = encoded

		err := ResponderHandshake(session, rw)
		if err == nil {
			t.Fatal("expected error for cipher suite mismatch")
		}
		verifyAlert(t, rw.writeData.Bytes(), err)
	})
}

func TestVerifyDataDifferentSecrets(t *testing.T) {
	// Two handshakes with different shared secrets must produce different verify_data
	transcript := []byte("same transcript data for both")

	secret1 := make([]byte, 32)
	secret2 := make([]byte, 32)
	for i := range secret1 {
		secret1[i] = byte(i)
		secret2[i] = byte(i + 128)
	}

	vd1, err := crypto.DeriveKeyMultiple(
		"CH-KEM-VPN-ClientFinished",
		[][]byte{secret1, transcript},
		32,
	)
	if err != nil {
		t.Fatalf("DeriveKeyMultiple failed: %v", err)
	}

	vd2, err := crypto.DeriveKeyMultiple(
		"CH-KEM-VPN-ClientFinished",
		[][]byte{secret2, transcript},
		32,
	)
	if err != nil {
		t.Fatalf("DeriveKeyMultiple failed: %v", err)
	}

	if bytes.Equal(vd1, vd2) {
		t.Error("verify_data with different shared secrets should differ")
	}
}
