package tunnel

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

func inplaceSessionPair(t testing.TB) (initiator, responder *Session) {
	t.Helper()
	secret := make([]byte, constants.CHKEMSharedSecretSize)
	if err := crypto.SecureRandom(secret); err != nil {
		t.Fatal(err)
	}
	var err error
	if initiator, err = NewSession(RoleInitiator); err != nil {
		t.Fatal(err)
	}
	if responder, err = NewSession(RoleResponder); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*Session{initiator, responder} {
		if err := s.InitializeKeys(secret, constants.CipherSuiteAES256GCM); err != nil {
			t.Fatal(err)
		}
	}
	return initiator, responder
}

// The in-place frame is byte-identical to the legacy Encrypt plus EncodeData frame.
func TestEncryptFrameToMatchesLegacyFrame(t *testing.T) {
	secret := make([]byte, constants.CHKEMSharedSecretSize)
	_ = crypto.SecureRandom(secret)
	mk := func() *Session {
		s, _ := NewSession(RoleInitiator)
		if err := s.InitializeKeys(secret, constants.CipherSuiteAES256GCM); err != nil {
			t.Fatal(err)
		}
		return s
	}
	legacy, inplace := mk(), mk()
	codec := protocol.NewCodec()
	for _, n := range []int{0, 1, 63, 1400, 60000} {
		pt := bytes.Repeat([]byte{byte(n)}, n)
		ct, seq, err := legacy.Encrypt(pt)
		if err != nil {
			t.Fatal(err)
		}
		want, err := codec.EncodeData(seq, ct)
		if err != nil {
			t.Fatal(err)
		}
		got, gseq, err := inplace.encryptFrameTo(nil, pt, nil)
		if err != nil {
			t.Fatal(err)
		}
		if gseq != seq || !bytes.Equal(got, want) {
			t.Fatalf("size %d: in-place frame differs from the legacy frame (seq %d vs %d)", n, gseq, seq)
		}
	}
}

// Frames cross the old and new paths in both directions.
func TestInplaceFramesInteroperateWithLegacyReceiver(t *testing.T) {
	codec := protocol.NewCodec()
	tx, rx := inplaceSessionPair(t)
	frame, _, err := tx.encryptFrameTo(nil, []byte("hello"), nil)
	if err != nil {
		t.Fatal(err)
	}
	seq, ct, err := codec.DecodeData(frame)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := rx.Decrypt(ct, seq) // unchanged receiver
	if err != nil || string(pt) != "hello" {
		t.Fatalf("legacy receiver: %q, %v", pt, err)
	}

	ct2, seq2, err := tx.Encrypt([]byte("world")) // unchanged sender
	if err != nil {
		t.Fatal(err)
	}
	legacy, _ := codec.EncodeData(seq2, ct2)
	seq3, ct3, _ := codec.DecodeData(legacy)
	pt, err = rx.decryptDataTo(nil, ct3, seq3, legacy[protocol.HeaderSize:protocol.HeaderSize+8], nil)
	if err != nil || string(pt) != "world" {
		t.Fatalf("new receiver on a legacy frame: %q, %v", pt, err)
	}
}

func TestEncryptFrameToRejectsOversize(t *testing.T) {
	tx, _ := inplaceSessionPair(t)
	if _, _, err := tx.encryptFrameTo(nil, make([]byte, constants.MaxPayloadSize), nil); err == nil {
		t.Fatal("a plaintext whose ciphertext exceeds MaxPayloadSize was framed")
	}
	if _, seq, err := tx.encryptFrameTo(nil, []byte("x"), nil); err != nil || seq != 0 {
		t.Fatalf("a rejected oversize record consumed a sequence number: seq=%d err=%v", seq, err)
	}
}

type sinkConn struct{ net.Conn }

func (sinkConn) Write(p []byte) (int, error)      { return len(p), nil }
func (sinkConn) SetWriteDeadline(time.Time) error { return nil }
func (sinkConn) Read([]byte) (int, error)         { return 0, io.EOF }

func TestStreamSendAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector drops pooled buffers and adds allocations")
	}
	tx, _ := inplaceSessionPair(t)
	tr := &Transport{session: tx, conn: sinkConn{}, codec: protocol.NewCodec()}
	payload := make([]byte, 1400)
	_ = tr.sealAndWrite(payload) // warm the frame pool
	if got := quietAllocs(0, func() { _ = tr.sealAndWrite(payload) }); got != 0 {
		t.Fatalf("steady-state stream send allocates %v times per record, want 0", got)
	}
	batch := [][]byte{payload, payload, payload, payload}
	_ = tr.sealAndWriteBatch(batch)
	if got := quietAllocs(0, func() { _ = tr.sealAndWriteBatch(batch) }); got != 0 {
		t.Fatalf("steady-state batch send allocates %v times per batch, want 0", got)
	}
}

func TestStreamReceiveAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector adds allocations")
	}
	tx, rx := inplaceSessionPair(t)
	codec := protocol.NewCodec()
	frame, _, _ := tx.encryptFrameTo(nil, make([]byte, 1400), nil)
	tr := &Transport{session: rx, codec: codec}
	// Replay protection rejects a repeated sequence number, so measure one fresh
	// frame per run.
	frames := make([][]byte, 0, 4096)
	for i := 0; i < 4096; i++ {
		f, _, _ := tx.encryptFrameTo(nil, make([]byte, 1400), nil)
		frames = append(frames, f)
	}
	_ = frame
	i := 0
	if got := testing.AllocsPerRun(1000, func() {
		_, _ = tr.handleData(frames[i])
		i++
	}); got > 1 {
		t.Fatalf("stream receive allocates %v times per record, want at most 1 (the plaintext)", got)
	}
}
