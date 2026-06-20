// Package conformance holds the cross-implementation known-answer vectors for the
// Quantum-Go protocol. The test regenerates every vector from the implementation and
// checks it against the committed testdata/conformance/vectors.json, so an
// independent implementation can validate byte-for-byte against the same file. See
// testdata/conformance/README.md for the file format and the reproduction recipe.
package conformance

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/sara-star-quant/quantum-go/internal/constants"
	"github.com/sara-star-quant/quantum-go/pkg/chkem"
	"github.com/sara-star-quant/quantum-go/pkg/crypto"
	"github.com/sara-star-quant/quantum-go/pkg/protocol"
)

var update = flag.Bool("update", false, "regenerate testdata/conformance/vectors.json")

const (
	vectorsPath   = "../../testdata/conformance/vectors.json"
	formatVersion = 1
)

// Vectors is the committed conformance artifact. Fields serialize in declaration
// order, so the canonical (compact) marshaling and its digest are stable.
type Vectors struct {
	FormatVersion int            `json:"format_version"`
	Note          string         `json:"note"`
	KEMSuites     []KEMVector    `json:"kem_suites"`
	KeySchedule   KeyScheduleVec `json:"key_schedule"`
	AuthFolds     AuthFoldVec    `json:"auth_folds"`
	WireMessages  []WireVector   `json:"wire_messages"`
	Records       []RecordVector `json:"records"`
	Digest        string         `json:"digest"`
}

type KEMVector struct {
	ID           uint16 `json:"id"`
	Name         string `json:"name"`
	Seed         string `json:"seed"`
	PublicKey    string `json:"public_key"`
	EncapSeed    string `json:"encap_seed"`
	Ciphertext   string `json:"ciphertext"`
	SharedSecret string `json:"shared_secret"`
}

type KeyScheduleVec struct {
	MasterSecret         string `json:"master_secret"`
	Transcript           string `json:"transcript"`
	HandshakeInitiatorK  string `json:"handshake_initiator_key"`
	HandshakeResponderK  string `json:"handshake_responder_key"`
	HandshakeInitiatorIV string `json:"handshake_initiator_iv"`
	HandshakeResponderIV string `json:"handshake_responder_iv"`
	TrafficInitiatorKey  string `json:"traffic_initiator_key"`
	TrafficResponderKey  string `json:"traffic_responder_key"`
	StreamInitiatorPfx   string `json:"stream_initiator_nonce_prefix"`
	StreamResponderPfx   string `json:"stream_responder_nonce_prefix"`
	DgramInitiatorPfx    string `json:"datagram_initiator_nonce_prefix"`
	DgramResponderPfx    string `json:"datagram_responder_nonce_prefix"`
	ClientFinished       string `json:"client_finished_verify_data"`
	ServerFinished       string `json:"server_finished_verify_data"`
}

type AuthFoldVec struct {
	EphemeralSecret string `json:"ephemeral_secret"`
	StaticSecret    string `json:"static_secret"`
	AuthFolded      string `json:"authenticated_secret"`
	PSK             string `json:"psk"`
	PSKFolded       string `json:"psk_secret"`
}

type WireVector struct {
	Name    string `json:"name"`
	Encoded string `json:"encoded"`
}

type RecordVector struct {
	CipherSuite uint16 `json:"cipher_suite"`
	TrafficKey  string `json:"traffic_key"`
	NoncePrefix string `json:"nonce_prefix"`
	Seq         uint64 `json:"seq"`
	Plaintext   string `json:"plaintext"`
	Ciphertext  string `json:"ciphertext"`
	DataRecord  string `json:"data_record"`
}

// filled returns n bytes where b[i] = start+i (mod 256), a deterministic fixed input.
func filled(n, start int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(start + i)
	}
	return b
}

func hx(b []byte) string { return hex.EncodeToString(b) }

// generate reproduces every vector from the implementation, failing the test on any
// internal cross-check mismatch (e.g. reconstructed ciphertext vs Decapsulate).
func generate(t *testing.T) Vectors {
	t.Helper()
	v := Vectors{
		FormatVersion: formatVersion,
		Note:          "Quantum-Go conformance vectors. See testdata/conformance/README.md.",
	}

	v.KEMSuites = append(v.KEMSuites, chkemV1Vector(t), xwingVector(t))
	v.KeySchedule = keyScheduleVector(t)
	v.AuthFolds = authFoldVector(t)
	v.WireMessages = wireVectors(t, v.KEMSuites[0])
	v.Records = recordVectors(t)

	v.Digest = digest(v)
	return v
}

func chkemV1Vector(t *testing.T) KEMVector {
	t.Helper()
	suite, ok := chkem.GetSuite(chkem.SuiteCHKEMv1)
	if !ok {
		t.Fatal("CH-KEM-v1 not registered")
	}
	seed := filled(suite.SeedSize(), 1)
	kp, err := suite.ParseKeyPair(seed)
	if err != nil {
		t.Fatalf("ParseKeyPair: %v", err)
	}
	pub := kp.PublicKey()

	// Reconstruct the v1 ciphertext per PROTOCOL.md Section 4.1 from fixed coins.
	x25519Scalar := filled(constants.X25519PrivateKeySize, 0x40)
	mlkemCoins := filled(32, 0x80)
	encapSeed := append(append([]byte{}, x25519Scalar...), mlkemCoins...)

	eph, err := crypto.NewX25519KeyPairFromBytes(x25519Scalar)
	if err != nil {
		t.Fatalf("ephemeral X25519: %v", err)
	}
	kx, err := crypto.X25519(eph.PrivateKey, pub.X25519PublicKey())
	if err != nil {
		t.Fatalf("X25519 DH: %v", err)
	}
	ctMLKEM, km, err := crypto.MLKEMEncapsulateWithSeed(pub.MLKEMPublicKey(), mlkemCoins)
	if err != nil {
		t.Fatalf("ML-KEM encapsulate: %v", err)
	}
	ctEph := eph.PublicKeyBytes()

	var ver [2]byte
	binary.BigEndian.PutUint16(ver[:], constants.ProtocolVersion)
	transcript, err := crypto.TranscriptHash(
		pub.X25519PublicKey().Bytes(), pub.MLKEMPublicKey().Bytes(),
		ctEph, ctMLKEM, ver[:], []byte{byte(chkem.RoleResponder)},
	)
	if err != nil {
		t.Fatalf("TranscriptHash: %v", err)
	}
	secret, err := crypto.DeriveCHKEMSecret(kx, km, transcript)
	if err != nil {
		t.Fatalf("DeriveCHKEMSecret: %v", err)
	}
	ct := append(append([]byte{}, ctEph...), ctMLKEM...)

	// Correctness guard: the real combiner (via Decapsulate) must recover the same
	// secret from the reconstructed ciphertext.
	ctObj, err := suite.ParseCiphertext(ct)
	if err != nil {
		t.Fatalf("ParseCiphertext: %v", err)
	}
	got, err := suite.Decapsulate(ctObj, kp, chkem.RoleInitiator)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("CH-KEM-v1 reconstruction diverged from Decapsulate")
	}

	return KEMVector{
		ID: uint16(chkem.SuiteCHKEMv1), Name: "CH-KEM-v1",
		Seed: hx(seed), PublicKey: hx(pub.Bytes()), EncapSeed: hx(encapSeed),
		Ciphertext: hx(ct), SharedSecret: hx(secret),
	}
}

func xwingVector(t *testing.T) KEMVector {
	t.Helper()
	suite, ok := chkem.GetSuite(chkem.SuiteXWing)
	if !ok {
		t.Fatal("X-Wing not registered")
	}
	seed := filled(suite.SeedSize(), 1)
	kp, err := suite.ParseKeyPair(seed)
	if err != nil {
		t.Fatalf("ParseKeyPair: %v", err)
	}
	pub := kp.PublicKey().Bytes()
	eseed := filled(64, 0x40)
	ct, ss, err := crypto.XWingEncapsulateWithSeed(pub, eseed)
	if err != nil {
		t.Fatalf("XWingEncapsulateWithSeed: %v", err)
	}
	ctObj, err := suite.ParseCiphertext(ct)
	if err != nil {
		t.Fatalf("ParseCiphertext: %v", err)
	}
	got, err := suite.Decapsulate(ctObj, kp, chkem.RoleInitiator)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(got, ss) {
		t.Fatal("X-Wing Decapsulate did not match encapsulated secret")
	}
	return KEMVector{
		ID: uint16(chkem.SuiteXWing), Name: "X-Wing",
		Seed: hx(seed), PublicKey: hx(pub), EncapSeed: hx(eseed),
		Ciphertext: hx(ct), SharedSecret: hx(ss),
	}
}

func keyScheduleVector(t *testing.T) KeyScheduleVec {
	t.Helper()
	master := filled(constants.CHKEMSharedSecretSize, 0x11)
	transcript := filled(48, 0x22)

	hik, hrk, hiv, hrv, err := crypto.DeriveHandshakeKeys(master)
	if err != nil {
		t.Fatalf("DeriveHandshakeKeys: %v", err)
	}
	tik, trk, err := crypto.DeriveTrafficKeys(master)
	if err != nil {
		t.Fatalf("DeriveTrafficKeys: %v", err)
	}
	sip, srp, err := crypto.DeriveStreamNoncePrefixes(master)
	if err != nil {
		t.Fatalf("DeriveStreamNoncePrefixes: %v", err)
	}
	dip, drp, err := crypto.DeriveDatagramNoncePrefixes(master)
	if err != nil {
		t.Fatalf("DeriveDatagramNoncePrefixes: %v", err)
	}
	cf, err := crypto.DeriveKeyMultiple("CH-KEM-Tunnel-ClientFinished", [][]byte{master, transcript}, 32)
	if err != nil {
		t.Fatalf("client finished: %v", err)
	}
	sf, err := crypto.DeriveKeyMultiple("CH-KEM-Tunnel-ServerFinished", [][]byte{master, transcript}, 32)
	if err != nil {
		t.Fatalf("server finished: %v", err)
	}
	return KeyScheduleVec{
		MasterSecret: hx(master), Transcript: hx(transcript),
		HandshakeInitiatorK: hx(hik), HandshakeResponderK: hx(hrk),
		HandshakeInitiatorIV: hx(hiv), HandshakeResponderIV: hx(hrv),
		TrafficInitiatorKey: hx(tik), TrafficResponderKey: hx(trk),
		StreamInitiatorPfx: hx(sip), StreamResponderPfx: hx(srp),
		DgramInitiatorPfx: hx(dip), DgramResponderPfx: hx(drp),
		ClientFinished: hx(cf), ServerFinished: hx(sf),
	}
}

func authFoldVector(t *testing.T) AuthFoldVec {
	t.Helper()
	eph := filled(constants.CHKEMSharedSecretSize, 0x33)
	stat := filled(constants.CHKEMSharedSecretSize, 0x44)
	psk := filled(constants.CHKEMSharedSecretSize, 0x55)
	master := filled(constants.CHKEMSharedSecretSize, 0x11)
	authFold, err := crypto.DeriveAuthenticatedSecret(eph, stat)
	if err != nil {
		t.Fatalf("DeriveAuthenticatedSecret: %v", err)
	}
	pskFold, err := crypto.DerivePSKSecret(master, psk)
	if err != nil {
		t.Fatalf("DerivePSKSecret: %v", err)
	}
	return AuthFoldVec{
		EphemeralSecret: hx(eph), StaticSecret: hx(stat), AuthFolded: hx(authFold),
		PSK: hx(psk), PSKFolded: hx(pskFold),
	}
}

func wireVectors(t *testing.T, v1 KEMVector) []WireVector {
	t.Helper()
	codec := protocol.NewCodec()
	pub, _ := hex.DecodeString(v1.PublicKey)
	ct, _ := hex.DecodeString(v1.Ciphertext)
	random := filled(32, 0x66)
	sessionID := filled(constants.SessionIDSize, 0x77)
	verifyData := filled(32, 0x88)

	ch := &protocol.ClientHello{
		Version: protocol.Current, Random: random, SessionID: sessionID,
		KEMSuite: uint16(chkem.SuiteCHKEMv1), KEMSuites: []uint16{uint16(chkem.SuiteCHKEMv1), uint16(chkem.SuiteXWing)},
		CHKEMPublicKey: pub,
		CipherSuites:   []constants.CipherSuite{constants.CipherSuiteAES256GCM, constants.CipherSuiteChaCha20Poly1305},
	}
	sh := &protocol.ServerHello{
		Version: protocol.Current, Random: random, SessionID: sessionID,
		KEMSuite: uint16(chkem.SuiteCHKEMv1), CHKEMCiphertext: ct, CipherSuite: constants.CipherSuiteAES256GCM,
	}
	hrr := &protocol.HelloRetryRequest{Version: protocol.Current, KEMSuite: uint16(chkem.SuiteCHKEMv1)}

	chBytes, err := codec.EncodeClientHello(ch)
	if err != nil {
		t.Fatalf("EncodeClientHello: %v", err)
	}
	if _, err := codec.DecodeClientHello(chBytes); err != nil {
		t.Fatalf("ClientHello round-trip: %v", err)
	}
	shBytes, err := codec.EncodeServerHello(sh)
	if err != nil {
		t.Fatalf("EncodeServerHello: %v", err)
	}
	if _, err := codec.DecodeServerHello(shBytes); err != nil {
		t.Fatalf("ServerHello round-trip: %v", err)
	}
	hrrBytes, err := codec.EncodeHelloRetryRequest(hrr)
	if err != nil {
		t.Fatalf("EncodeHelloRetryRequest: %v", err)
	}
	if _, err := codec.DecodeHelloRetryRequest(hrrBytes); err != nil {
		t.Fatalf("HelloRetryRequest round-trip: %v", err)
	}
	finBytes, err := codec.EncodeFinished(protocol.MessageTypeClientFinished, verifyData)
	if err != nil {
		t.Fatalf("EncodeFinished: %v", err)
	}

	return []WireVector{
		{Name: "client_hello", Encoded: hx(chBytes)},
		{Name: "server_hello", Encoded: hx(shBytes)},
		{Name: "hello_retry_request", Encoded: hx(hrrBytes)},
		{Name: "client_finished", Encoded: hx(finBytes)},
	}
}

func recordVectors(t *testing.T) []RecordVector {
	t.Helper()
	master := filled(constants.CHKEMSharedSecretSize, 0x11)
	key, _, err := crypto.DeriveTrafficKeys(master)
	if err != nil {
		t.Fatalf("DeriveTrafficKeys: %v", err)
	}
	prefix, _, err := crypto.DeriveStreamNoncePrefixes(master)
	if err != nil {
		t.Fatalf("DeriveStreamNoncePrefixes: %v", err)
	}
	const seq = uint64(7)
	plaintext := []byte("conformance record vector")

	suites := []constants.CipherSuite{constants.CipherSuiteAES256GCM}
	if !crypto.FIPSMode() {
		suites = append(suites, constants.CipherSuiteChaCha20Poly1305)
	}

	var out []RecordVector
	for _, cs := range suites {
		aead, err := crypto.NewAEAD(cs, key)
		if err != nil {
			t.Fatalf("NewAEAD(%#x): %v", cs, err)
		}
		nonce := make([]byte, constants.AESNonceSize)
		copy(nonce[:constants.DatagramNoncePrefixSize], prefix)
		binary.BigEndian.PutUint64(nonce[constants.DatagramNoncePrefixSize:], seq)
		aad := make([]byte, 8)
		binary.BigEndian.PutUint64(aad, seq)

		ct, err := aead.SealWithNonce(nonce, plaintext, aad)
		if err != nil {
			t.Fatalf("SealWithNonce: %v", err)
		}
		record, err := protocol.NewCodec().EncodeData(seq, ct)
		if err != nil {
			t.Fatalf("EncodeData: %v", err)
		}
		out = append(out, RecordVector{
			CipherSuite: uint16(cs), TrafficKey: hx(key), NoncePrefix: hx(prefix), Seq: seq,
			Plaintext: hx(plaintext), Ciphertext: hx(ct), DataRecord: hx(record),
		})
	}
	return out
}

// digest is SHA-256 over the compact JSON of v with the Digest field cleared.
func digest(v Vectors) string {
	v.Digest = ""
	b, _ := json.Marshal(v)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func canonical(v Vectors) []byte {
	b, _ := json.Marshal(v)
	return b
}

func TestConformanceVectors(t *testing.T) {
	got := generate(t)

	if *update {
		out, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(vectorsPath, append(out, '\n'), 0o644); err != nil {
			t.Fatalf("write %s: %v", vectorsPath, err)
		}
		t.Logf("updated %s", vectorsPath)
		return
	}

	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read %s (run with -update to generate): %v", vectorsPath, err)
	}
	var want Vectors
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("unmarshal %s: %v", vectorsPath, err)
	}

	// The committed file's own digest must be self-consistent over its full contents
	// (catches a tampered digest), regardless of build.
	if want.Digest != digest(want) {
		t.Fatal("committed vectors.json digest is inconsistent with its contents")
	}

	// Under the FIPS build the implementation cannot produce the ChaCha20-Poly1305
	// record, so compare against the FIPS-approved subset of the committed records.
	if crypto.FIPSMode() {
		want.Records = fipsApprovedRecords(want.Records)
	}

	// Compare CONTENT (digests cleared): the implementation must reproduce the committed
	// file field-for-field. Catches drift and a tampered field; run -update for an
	// intended change and scrutinize the diff.
	got.Digest, want.Digest = "", ""
	if !bytes.Equal(canonical(got), canonical(want)) {
		t.Fatal("implementation output does not match testdata/conformance/vectors.json (run -update if intended, and scrutinize the diff)")
	}
}

// fipsApprovedRecords keeps only the records whose cipher suite is FIPS-approved.
func fipsApprovedRecords(in []RecordVector) []RecordVector {
	out := make([]RecordVector, 0, len(in))
	for _, r := range in {
		if constants.CipherSuite(r.CipherSuite).IsFIPSApproved() {
			out = append(out, r)
		}
	}
	return out
}
