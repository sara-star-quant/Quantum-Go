package protocol_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/pzverkov/quantum-go/internal/constants"
	qerrors "github.com/pzverkov/quantum-go/internal/errors"
	"github.com/pzverkov/quantum-go/pkg/chkem"
	"github.com/pzverkov/quantum-go/pkg/crypto"
	"github.com/pzverkov/quantum-go/pkg/protocol"
)

// --- ClientHello Tests ---

func TestEncodeDecodeClientHello(t *testing.T) {
	codec := protocol.NewCodec()
	kp, err := chkem.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	random := make([]byte, 32)
	_ = crypto.SecureRandom(random)

	original := &protocol.ClientHello{
		Version:        protocol.Current,
		Random:         random,
		SessionID:      nil, // New session
		CHKEMPublicKey: kp.PublicKey().Bytes(),
		CipherSuites: []constants.CipherSuite{
			constants.CipherSuiteAES256GCM,
			constants.CipherSuiteChaCha20Poly1305,
		},
	}

	// Encode
	encoded, err := codec.EncodeClientHello(original)
	if err != nil {
		t.Fatalf("EncodeClientHello failed: %v", err)
	}

	// Verify message type
	if protocol.MessageType(encoded[0]) != protocol.MessageTypeClientHello {
		t.Errorf("wrong message type: got %d, want %d", encoded[0], protocol.MessageTypeClientHello)
	}

	// Decode
	decoded, err := codec.DecodeClientHello(encoded)
	if err != nil {
		t.Fatalf("DecodeClientHello failed: %v", err)
	}

	// Verify fields
	if decoded.Version != original.Version {
		t.Errorf("version mismatch: got %v, want %v", decoded.Version, original.Version)
	}
	if !bytes.Equal(decoded.Random, original.Random) {
		t.Error("random mismatch")
	}
	if !bytes.Equal(decoded.CHKEMPublicKey, original.CHKEMPublicKey) {
		t.Error("public key mismatch")
	}
	if len(decoded.CipherSuites) != len(original.CipherSuites) {
		t.Errorf("cipher suites count mismatch: got %d, want %d", len(decoded.CipherSuites), len(original.CipherSuites))
	}
	for i, cs := range decoded.CipherSuites {
		if cs != original.CipherSuites[i] {
			t.Errorf("cipher suite %d mismatch: got %d, want %d", i, cs, original.CipherSuites[i])
		}
	}
}

func TestClientHelloWithSessionID(t *testing.T) {
	codec := protocol.NewCodec()
	kp, _ := chkem.GenerateKeyPair()

	random := make([]byte, 32)
	sessionID := make([]byte, 16)
	_ = crypto.SecureRandom(random)
	_ = crypto.SecureRandom(sessionID)

	original := &protocol.ClientHello{
		Version:        protocol.Current,
		Random:         random,
		SessionID:      sessionID,
		CHKEMPublicKey: kp.PublicKey().Bytes(),
		CipherSuites:   []constants.CipherSuite{constants.CipherSuiteAES256GCM},
	}

	encoded, err := codec.EncodeClientHello(original)
	if err != nil {
		t.Fatalf("EncodeClientHello failed: %v", err)
	}

	decoded, err := codec.DecodeClientHello(encoded)
	if err != nil {
		t.Fatalf("DecodeClientHello failed: %v", err)
	}

	if !bytes.Equal(decoded.SessionID, original.SessionID) {
		t.Error("session ID mismatch")
	}
}

func TestDecodeClientHelloInvalidInputs(t *testing.T) {
	codec := protocol.NewCodec()

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{0x01}},
		{"header only", []byte{0x01, 0, 0, 0, 0}},
		{"wrong message type", []byte{0x02, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"truncated payload", []byte{0x01, 0, 0, 0, 100, 0, 0}}, // Claims 100 bytes, has 2
		{"huge length", []byte{0x01, 0xff, 0xff, 0xff, 0xff}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := codec.DecodeClientHello(tc.data)
			if err == nil {
				t.Error("expected error for invalid input")
			}
		})
	}
}

// --- ServerHello Tests ---

func TestEncodeDecodeServerHello(t *testing.T) {
	codec := protocol.NewCodec()
	kp, _ := chkem.GenerateKeyPair()
	ct, _, _ := chkem.Encapsulate(kp.PublicKey())

	random := make([]byte, 32)
	sessionID := make([]byte, constants.SessionIDSize)
	_ = crypto.SecureRandom(random)
	_ = crypto.SecureRandom(sessionID)

	original := &protocol.ServerHello{
		Version:         protocol.Current,
		Random:          random,
		SessionID:       sessionID,
		CHKEMCiphertext: ct.Bytes(),
		CipherSuite:     constants.CipherSuiteChaCha20Poly1305,
	}

	// Encode
	encoded, err := codec.EncodeServerHello(original)
	if err != nil {
		t.Fatalf("EncodeServerHello failed: %v", err)
	}

	// Verify message type
	if protocol.MessageType(encoded[0]) != protocol.MessageTypeServerHello {
		t.Errorf("wrong message type: got %d, want %d", encoded[0], protocol.MessageTypeServerHello)
	}

	// Decode
	decoded, err := codec.DecodeServerHello(encoded)
	if err != nil {
		t.Fatalf("DecodeServerHello failed: %v", err)
	}

	// Verify fields
	if decoded.Version != original.Version {
		t.Errorf("version mismatch: got %v, want %v", decoded.Version, original.Version)
	}
	if !bytes.Equal(decoded.Random, original.Random) {
		t.Error("random mismatch")
	}
	if !bytes.Equal(decoded.SessionID, original.SessionID) {
		t.Error("session ID mismatch")
	}
	if !bytes.Equal(decoded.CHKEMCiphertext, original.CHKEMCiphertext) {
		t.Error("ciphertext mismatch")
	}
	if decoded.CipherSuite != original.CipherSuite {
		t.Errorf("cipher suite mismatch: got %d, want %d", decoded.CipherSuite, original.CipherSuite)
	}
}

func TestDecodeServerHelloInvalidInputs(t *testing.T) {
	codec := protocol.NewCodec()

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{0x02}},
		{"header only", []byte{0x02, 0, 0, 0, 0}},
		{"wrong message type", []byte{0x01, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"truncated payload", []byte{0x02, 0, 0, 0, 100, 0, 0}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := codec.DecodeServerHello(tc.data)
			if err == nil {
				t.Error("expected error for invalid input")
			}
		})
	}
}

// --- Finished Message Tests ---

func TestEncodeDecodeFinished(t *testing.T) {
	codec := protocol.NewCodec()

	verifyData := make([]byte, 32)
	crypto.SecureRandom(verifyData)

	// Test ClientFinished
	encoded, err := codec.EncodeFinished(protocol.MessageTypeClientFinished, verifyData)
	if err != nil {
		t.Fatalf("EncodeFinished failed: %v", err)
	}

	if protocol.MessageType(encoded[0]) != protocol.MessageTypeClientFinished {
		t.Errorf("wrong message type: got %d, want %d", encoded[0], protocol.MessageTypeClientFinished)
	}

	decoded, err := codec.DecodeFinished(encoded)
	if err != nil {
		t.Fatalf("DecodeFinished failed: %v", err)
	}

	if !bytes.Equal(decoded, verifyData) {
		t.Error("verify data mismatch")
	}

	// Test ServerFinished
	encoded, err = codec.EncodeFinished(protocol.MessageTypeServerFinished, verifyData)
	if err != nil {
		t.Fatalf("EncodeFinished failed: %v", err)
	}

	if protocol.MessageType(encoded[0]) != protocol.MessageTypeServerFinished {
		t.Errorf("wrong message type: got %d, want %d", encoded[0], protocol.MessageTypeServerFinished)
	}
}

func TestEncodeFinishedInvalidVerifyData(t *testing.T) {
	codec := protocol.NewCodec()

	// Wrong size
	_, err := codec.EncodeFinished(protocol.MessageTypeClientFinished, []byte("short"))
	if err == nil {
		t.Error("expected error for invalid verify data size")
	}
}

func TestDecodeFinishedInvalidInputs(t *testing.T) {
	codec := protocol.NewCodec()

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{0x03, 0, 0, 0, 32}}, // Claims 32 bytes but has none
		{"wrong message type", []byte{0x10, 0, 0, 0, 32}}, // Data message type
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := codec.DecodeFinished(tc.data)
			if err == nil {
				t.Error("expected error for invalid input")
			}
		})
	}
}

// --- Data Message Tests ---

func TestEncodeDecodeData(t *testing.T) {
	codec := protocol.NewCodec()

	testCases := []struct {
		name    string
		seq     uint64
		payload []byte
	}{
		{"small payload", 1, []byte("hello")},
		{"zero sequence", 0, []byte("test")},
		{"large sequence", 0xFFFFFFFFFFFFFFFF, []byte("max seq")},
		{"empty payload", 42, []byte{}},
		{"1KB payload", 100, make([]byte, 1024)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.payload) > 0 && tc.payload[0] == 0 {
				crypto.SecureRandom(tc.payload)
			}

			encoded, err := codec.EncodeData(tc.seq, tc.payload)
			if err != nil {
				t.Fatalf("EncodeData failed: %v", err)
			}

			if protocol.MessageType(encoded[0]) != protocol.MessageTypeData {
				t.Errorf("wrong message type: got %d, want %d", encoded[0], protocol.MessageTypeData)
			}

			decodedSeq, decodedPayload, err := codec.DecodeData(encoded)
			if err != nil {
				t.Fatalf("DecodeData failed: %v", err)
			}

			if decodedSeq != tc.seq {
				t.Errorf("sequence mismatch: got %d, want %d", decodedSeq, tc.seq)
			}
			if !bytes.Equal(decodedPayload, tc.payload) {
				t.Error("payload mismatch")
			}
		})
	}
}

func TestEncodeDataTooLarge(t *testing.T) {
	codec := protocol.NewCodec()
	largePayload := make([]byte, constants.MaxPayloadSize+1)

	_, err := codec.EncodeData(0, largePayload)
	if err == nil {
		t.Error("expected error for payload too large")
	}
}

func TestDecodeDataInvalidInputs(t *testing.T) {
	codec := protocol.NewCodec()

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"header only", []byte{0x10, 0, 0, 0, 0}},
		{"too short for seq", []byte{0x10, 0, 0, 0, 4, 0, 0, 0, 0}}, // Need 8 bytes for seq
		{"wrong message type", []byte{0x01, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := codec.DecodeData(tc.data)
			if err == nil {
				t.Error("expected error for invalid input")
			}
		})
	}
}

// --- Alert Message Tests ---

func TestEncodeDecodeAlert(t *testing.T) {
	codec := protocol.NewCodec()

	testCases := []struct {
		name string
		code protocol.AlertCode
		desc string
	}{
		{"handshake failure", protocol.AlertCodeHandshakeFailure, "handshake failed"},
		{"close notify", protocol.AlertCodeCloseNotify, "connection closing"},
		{"empty description", protocol.AlertCodeInternalError, ""},
		{"long description", protocol.AlertCodeBadCiphertext, "this is a somewhat longer description that explains the error"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded := codec.EncodeAlert(tc.code, tc.desc)

			if protocol.MessageType(encoded[0]) != protocol.MessageTypeAlert {
				t.Errorf("wrong message type: got %d, want %d", encoded[0], protocol.MessageTypeAlert)
			}

			decodedCode, decodedDesc, err := codec.DecodeAlert(encoded)
			if err != nil {
				t.Fatalf("DecodeAlert failed: %v", err)
			}

			if decodedCode != tc.code {
				t.Errorf("code mismatch: got %d, want %d", decodedCode, tc.code)
			}
			if decodedDesc != tc.desc {
				t.Errorf("description mismatch: got %q, want %q", decodedDesc, tc.desc)
			}
		})
	}
}

func TestEncodeAlertDescriptionTruncation(t *testing.T) {
	codec := protocol.NewCodec()

	// Description longer than 255 bytes should be truncated (length stored in 1 byte)
	longDesc := make([]byte, 300)
	for i := range longDesc {
		longDesc[i] = 'A'
	}

	encoded := codec.EncodeAlert(protocol.AlertCodeInternalError, string(longDesc))
	_, decodedDesc, err := codec.DecodeAlert(encoded)
	if err != nil {
		t.Fatalf("DecodeAlert failed: %v", err)
	}

	if len(decodedDesc) != 255 {
		t.Errorf("description should be truncated to 255 bytes, got %d", len(decodedDesc))
	}
}

func TestDecodeAlertInvalidInputs(t *testing.T) {
	codec := protocol.NewCodec()

	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{0xF0, 0, 0, 0, 1, 0x01}}, // Need at least 2 bytes payload
		{"wrong message type", []byte{0x10, 0, 0, 0, 2, 0x01, 0}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := codec.DecodeAlert(tc.data)
			if err == nil {
				t.Error("expected error for invalid input")
			}
		})
	}
}

// --- ReadMessage Tests ---

func TestReadMessage(t *testing.T) {
	codec := protocol.NewCodec()
	kp, _ := chkem.GenerateKeyPair()

	random := make([]byte, 32)
	_ = crypto.SecureRandom(random)

	original := &protocol.ClientHello{
		Version:        protocol.Current,
		Random:         random,
		SessionID:      nil,
		CHKEMPublicKey: kp.PublicKey().Bytes(),
		CipherSuites:   []constants.CipherSuite{constants.CipherSuiteAES256GCM},
	}

	encoded, _ := codec.EncodeClientHello(original)

	// Read from buffer
	reader := bytes.NewReader(encoded)
	msg, err := codec.ReadMessage(reader)
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}

	if !bytes.Equal(msg, encoded) {
		t.Error("read message doesn't match original")
	}
}

func TestReadMessageMultiple(t *testing.T) {
	codec := protocol.NewCodec()

	// Write multiple messages to buffer
	var buf bytes.Buffer

	msg1, _ := codec.EncodeData(1, []byte("first"))
	msg2, _ := codec.EncodeData(2, []byte("second"))
	msg3 := codec.EncodeAlert(protocol.AlertCodeCloseNotify, "closing")

	buf.Write(msg1)
	buf.Write(msg2)
	buf.Write(msg3)

	// Read them back
	read1, err := codec.ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage 1 failed: %v", err)
	}
	if !bytes.Equal(read1, msg1) {
		t.Error("message 1 mismatch")
	}

	read2, err := codec.ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage 2 failed: %v", err)
	}
	if !bytes.Equal(read2, msg2) {
		t.Error("message 2 mismatch")
	}

	read3, err := codec.ReadMessage(&buf)
	if err != nil {
		t.Fatalf("ReadMessage 3 failed: %v", err)
	}
	if !bytes.Equal(read3, msg3) {
		t.Error("message 3 mismatch")
	}

	// Should get EOF now
	_, err = codec.ReadMessage(&buf)
	if err != io.EOF {
		t.Errorf("expected EOF, got %v", err)
	}
}

func TestReadMessageTooLarge(t *testing.T) {
	codec := protocol.NewCodec()

	// Create a message claiming to be larger than MaxMessageSize
	header := make([]byte, protocol.HeaderSize)
	header[0] = byte(protocol.MessageTypeData)
	binary.BigEndian.PutUint32(header[1:], protocol.MaxMessageSize+1)

	reader := bytes.NewReader(header)
	_, err := codec.ReadMessage(reader)
	if err == nil {
		t.Error("expected error for message too large")
	}
	if !qerrors.Is(err, qerrors.ErrMessageTooLarge) {
		t.Errorf("expected ErrMessageTooLarge, got %v", err)
	}
}

func TestReadMessageTruncated(t *testing.T) {
	codec := protocol.NewCodec()

	// Header claims 100 bytes payload but we only provide 10
	header := make([]byte, protocol.HeaderSize+10)
	header[0] = byte(protocol.MessageTypeData)
	binary.BigEndian.PutUint32(header[1:], 100)

	reader := bytes.NewReader(header)
	_, err := codec.ReadMessage(reader)
	if err == nil {
		t.Error("expected error for truncated message")
	}
}

// --- GetMessageType Tests ---

func TestGetMessageType(t *testing.T) {
	codec := protocol.NewCodec()

	tests := []struct {
		data     []byte
		expected protocol.MessageType
		wantErr  bool
	}{
		{[]byte{0x01}, protocol.MessageTypeClientHello, false},
		{[]byte{0x02}, protocol.MessageTypeServerHello, false},
		{[]byte{0x03}, protocol.MessageTypeClientFinished, false},
		{[]byte{0x04}, protocol.MessageTypeServerFinished, false},
		{[]byte{0x10}, protocol.MessageTypeData, false},
		{[]byte{0xF0}, protocol.MessageTypeAlert, false},
		{[]byte{}, 0, true}, // Empty
	}

	for _, tc := range tests {
		msgType, err := codec.GetMessageType(tc.data)
		if tc.wantErr {
			if err == nil {
				t.Errorf("expected error for data %v", tc.data)
			}
		} else {
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if msgType != tc.expected {
				t.Errorf("message type mismatch: got %d, want %d", msgType, tc.expected)
			}
		}
	}
}

// --- Message Validation Tests ---

func TestClientHelloValidation(t *testing.T) {
	kp, _ := chkem.GenerateKeyPair()

	tests := []struct {
		name    string
		modify  func(*protocol.ClientHello)
		wantErr bool
	}{
		{
			name:    "valid",
			modify:  func(m *protocol.ClientHello) {},
			wantErr: false,
		},
		{
			name: "wrong random size",
			modify: func(m *protocol.ClientHello) {
				m.Random = make([]byte, 16)
			},
			wantErr: true,
		},
		{
			name: "wrong public key size",
			modify: func(m *protocol.ClientHello) {
				m.CHKEMPublicKey = make([]byte, 100)
			},
			wantErr: true,
		},
		{
			name: "empty cipher suites",
			modify: func(m *protocol.ClientHello) {
				m.CipherSuites = nil
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			random := make([]byte, 32)
			crypto.SecureRandom(random)

			msg := &protocol.ClientHello{
				Version:        protocol.Current,
				Random:         random,
				SessionID:      nil,
				CHKEMPublicKey: kp.PublicKey().Bytes(),
				CipherSuites:   []constants.CipherSuite{constants.CipherSuiteAES256GCM},
			}
			tc.modify(msg)

			err := msg.Validate()
			if tc.wantErr && err == nil {
				t.Error("expected validation error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestServerHelloValidation(t *testing.T) {
	kp, _ := chkem.GenerateKeyPair()
	ct, _, _ := chkem.Encapsulate(kp.PublicKey())

	tests := []struct {
		name    string
		modify  func(*protocol.ServerHello)
		wantErr bool
	}{
		{
			name:    "valid",
			modify:  func(m *protocol.ServerHello) {},
			wantErr: false,
		},
		{
			name: "wrong random size",
			modify: func(m *protocol.ServerHello) {
				m.Random = make([]byte, 16)
			},
			wantErr: true,
		},
		{
			name: "wrong session ID size",
			modify: func(m *protocol.ServerHello) {
				m.SessionID = make([]byte, 8)
			},
			wantErr: true,
		},
		{
			name: "wrong ciphertext size",
			modify: func(m *protocol.ServerHello) {
				m.CHKEMCiphertext = make([]byte, 100)
			},
			wantErr: true,
		},
		{
			name: "unsupported cipher suite",
			modify: func(m *protocol.ServerHello) {
				m.CipherSuite = 0xFF
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			random := make([]byte, 32)
			sessionID := make([]byte, constants.SessionIDSize)
			crypto.SecureRandom(random)
			crypto.SecureRandom(sessionID)

			msg := &protocol.ServerHello{
				Version:         protocol.Current,
				Random:          random,
				SessionID:       sessionID,
				CHKEMCiphertext: ct.Bytes(),
				CipherSuite:     constants.CipherSuiteAES256GCM,
			}
			tc.modify(msg)

			err := msg.Validate()
			if tc.wantErr && err == nil {
				t.Error("expected validation error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

// --- Version Tests ---

func TestVersionCompatibility(t *testing.T) {
	current := protocol.Current

	tests := []struct {
		name       string
		version    protocol.Version
		compatible bool
	}{
		{"same version", current, true},
		{"same major different minor", protocol.Version{Major: current.Major, Minor: current.Minor + 1}, true},
		{"different major", protocol.Version{Major: current.Major + 1, Minor: 0}, false},
		{"older major", protocol.Version{Major: current.Major - 1, Minor: 0}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.version.IsCompatible(current) != tc.compatible {
				t.Errorf("expected compatible=%v for version %v", tc.compatible, tc.version)
			}
		})
	}
}

// --- Roundtrip Consistency Tests ---

func TestMultipleRoundtrips(t *testing.T) {
	codec := protocol.NewCodec()
	kp, _ := chkem.GenerateKeyPair()

	random := make([]byte, 32)
	_ = crypto.SecureRandom(random)

	original := &protocol.ClientHello{
		Version:        protocol.Current,
		Random:         random,
		SessionID:      nil,
		CHKEMPublicKey: kp.PublicKey().Bytes(),
		CipherSuites:   []constants.CipherSuite{constants.CipherSuiteAES256GCM},
	}

	// Encode and decode multiple times
	var lastEncoded []byte
	for i := 0; i < 10; i++ {
		encoded, err := codec.EncodeClientHello(original)
		if err != nil {
			t.Fatalf("encode %d failed: %v", i, err)
		}

		if lastEncoded != nil && !bytes.Equal(encoded, lastEncoded) {
			t.Errorf("encoding not deterministic at iteration %d", i)
		}
		lastEncoded = encoded

		decoded, err := codec.DecodeClientHello(encoded)
		if err != nil {
			t.Fatalf("decode %d failed: %v", i, err)
		}

		if !bytes.Equal(decoded.CHKEMPublicKey, original.CHKEMPublicKey) {
			t.Errorf("public key changed at iteration %d", i)
		}
	}
}

// --- MessageType String Tests ---

func TestMessageTypeString(t *testing.T) {
	tests := []struct {
		mt       protocol.MessageType
		expected string
	}{
		{protocol.MessageTypeClientHello, "ClientHello"},
		{protocol.MessageTypeServerHello, "ServerHello"},
		{protocol.MessageTypeClientFinished, "ClientFinished"},
		{protocol.MessageTypeServerFinished, "ServerFinished"},
		{protocol.MessageTypeData, "Data"},
		{protocol.MessageTypeRekey, "Rekey"},
		{protocol.MessageTypePing, "Ping"},
		{protocol.MessageTypePong, "Pong"},
		{protocol.MessageTypeClose, "Close"},
		{protocol.MessageTypeAlert, "Alert"},
		{protocol.MessageType(0xFF), "Unknown"},
	}

	for _, tc := range tests {
		if tc.mt.String() != tc.expected {
			t.Errorf("MessageType(%d).String() = %q, want %q", tc.mt, tc.mt.String(), tc.expected)
		}
	}
}

// --- Version Tests ---

func TestVersionBytes(t *testing.T) {
	v := protocol.Version{Major: 1, Minor: 2}
	b := v.Bytes()

	if len(b) != 2 {
		t.Errorf("Bytes length: got %d, want 2", len(b))
	}
	if b[0] != 1 || b[1] != 2 {
		t.Errorf("Bytes: got %v, want [1, 2]", b)
	}
}

func TestVersionUint16(t *testing.T) {
	v := protocol.Version{Major: 1, Minor: 2}
	u := v.Uint16()

	expected := uint16(1)<<8 | uint16(2)
	if u != expected {
		t.Errorf("Uint16: got %d, want %d", u, expected)
	}
}

func TestParseVersion(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected protocol.Version
	}{
		{"valid", []byte{1, 2}, protocol.Version{Major: 1, Minor: 2}},
		{"too short", []byte{1}, protocol.Version{}},
		{"empty", []byte{}, protocol.Version{}},
		{"with extra", []byte{3, 4, 5, 6}, protocol.Version{Major: 3, Minor: 4}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := protocol.ParseVersion(tc.data)
			if v != tc.expected {
				t.Errorf("ParseVersion(%v) = %v, want %v", tc.data, v, tc.expected)
			}
		})
	}
}

func TestVersionString(t *testing.T) {
	tests := []struct {
		version  protocol.Version
		expected string
	}{
		{protocol.Version{Major: 1, Minor: 0}, "1.0"},
		{protocol.Version{Major: 2, Minor: 5}, "2.5"},
		{protocol.Version{Major: 0, Minor: 9}, "0.9"},
	}

	for _, tc := range tests {
		if tc.version.String() != tc.expected {
			t.Errorf("Version%v.String() = %q, want %q", tc.version, tc.version.String(), tc.expected)
		}
	}
}

func TestSupportedCipherSuites(t *testing.T) {
	suites := protocol.SupportedCipherSuites()

	if len(suites) != 2 {
		t.Errorf("SupportedCipherSuites length: got %d, want 2", len(suites))
	}

	// Check that both supported suites are present
	hasAES := false
	hasChaCha := false
	for _, s := range suites {
		if s == constants.CipherSuiteAES256GCM {
			hasAES = true
		}
		if s == constants.CipherSuiteChaCha20Poly1305 {
			hasChaCha = true
		}
	}

	if !hasAES {
		t.Error("SupportedCipherSuites missing AES-256-GCM")
	}
	if !hasChaCha {
		t.Error("SupportedCipherSuites missing ChaCha20-Poly1305")
	}
}

func TestPreferredCipherSuite(t *testing.T) {
	preferred := protocol.PreferredCipherSuite()

	if preferred != constants.CipherSuiteAES256GCM {
		t.Errorf("PreferredCipherSuite: got %d, want %d (AES-256-GCM)", preferred, constants.CipherSuiteAES256GCM)
	}
}

// --- Finished Message Validation Tests ---

func TestClientFinishedValidation(t *testing.T) {
	tests := []struct {
		name      string
		verifyLen int
		wantErr   bool
	}{
		{"valid", 32, false},
		{"too short", 16, true},
		{"too long", 64, true},
		{"empty", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := &protocol.ClientFinished{
				VerifyData: make([]byte, tc.verifyLen),
			}
			err := msg.Validate()
			if tc.wantErr && err == nil {
				t.Error("expected validation error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestServerFinishedValidation(t *testing.T) {
	tests := []struct {
		name      string
		verifyLen int
		wantErr   bool
	}{
		{"valid", 32, false},
		{"too short", 16, true},
		{"too long", 64, true},
		{"empty", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := &protocol.ServerFinished{
				VerifyData: make([]byte, tc.verifyLen),
			}
			err := msg.Validate()
			if tc.wantErr && err == nil {
				t.Error("expected validation error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}
