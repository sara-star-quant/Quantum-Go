package tunnel

import (
	"errors"
	"net"
	"testing"

	"github.com/pzverkov/quantum-go/internal/constants"
	qerrors "github.com/pzverkov/quantum-go/internal/errors"
	"github.com/pzverkov/quantum-go/pkg/protocol"
)

func TestHandshakeProcessClientFinishedErrors(t *testing.T) {
	session, _ := NewSession(RoleResponder)
	h := NewHandshake(session)

	// 1. Invalid state
	h.state = HandshakeStateInitial
	err := h.ProcessClientFinished([]byte("data"))
	if !errors.Is(err, qerrors.ErrInvalidState) {
		t.Errorf("expected ErrInvalidState, got %v", err)
	}

	// 2. Decryption failure
	h.state = HandshakeStateServerHelloSent
	h.recvCipher = session.recvCipher
	err = h.ProcessClientFinished([]byte("garbage"))
	if err == nil {
		t.Error("expected error for decryption failure in ProcessClientFinished")
	}
}

func TestHandshakeCreateServerFinishedErrors(t *testing.T) {
	session, _ := NewSession(RoleResponder)
	h := NewHandshake(session)

	// 1. sendCipher is nil
	_, err := h.CreateServerFinished()
	if !errors.Is(err, qerrors.ErrInvalidState) {
		t.Errorf("expected ErrInvalidState, got %v", err)
	}
}

func TestTransportReceiveErrors(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	session, _ := NewSession(RoleResponder)
	tr := &Transport{
		session: session,
		conn:    serverConn,
		codec:   protocol.NewCodec(),
	}

	// 1. Unknown message type
	go func() {
		_, _ = clientConn.Write([]byte{0xFF, 0, 0, 0, 0})
	}()
	_, err := tr.Receive()
	if err == nil {
		t.Error("expected error for unknown message type in Receive")
	}

	// 2. handleData decode error
	go func() {
		// Valid data type but empty payload
		_, _ = clientConn.Write([]byte{byte(protocol.MessageTypeData), 0, 0, 0, 0})
	}()
	_, err = tr.Receive()
	if err == nil {
		t.Error("expected error for handleData decode error")
	}
}

func TestTransportSendLargeData(t *testing.T) {
	session, _ := NewSession(RoleInitiator)
	tr := &Transport{
		session: session,
	}

	largeData := make([]byte, constants.MaxPayloadSize+1)
	err := tr.Send(largeData)
	if !errors.Is(err, qerrors.ErrMessageTooLarge) {
		t.Errorf("expected ErrMessageTooLarge, got %v", err)
	}
}

func TestSessionEdgeCases(t *testing.T) {
	s, _ := NewSession(RoleInitiator)

	// Check activation of pending keys
	s.pendingSendCipher = s.sendCipher
	s.rekeyActivationSeq = 100
	s.PacketsSent.Store(100)
	s.checkAndActivateSendCipher(100)
	if s.pendingSendCipher != nil {
		t.Error("pending send cipher should have been activated")
	}
}
