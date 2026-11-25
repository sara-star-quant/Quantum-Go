package protocol

import (
	"bytes"
	"testing"
)

// The decoders read attacker-controlled length fields before any authentication. These tests pin
// each length check at its exact boundary: one byte short is an error and never a panic or a
// short read, and the exact length decodes. They exist because a weekly mutation run showed that
// weakening several of these checks (a plus turned into a minus, a less-than into less-or-equal)
// failed no test.

func mustNotPanic(t *testing.T, what string, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", what, r)
		}
	}()
	fn()
}

func TestDecodeAlertBoundaries(t *testing.T) {
	c := NewCodec()
	for _, desc := range []string{"", "x", "handshake failure", string(bytes.Repeat([]byte{'a'}, 255))} {
		full := c.EncodeAlert(AlertLevelFatal, AlertCode(7), desc)

		level, code, got, err := c.DecodeAlert(full)
		if err != nil || level != AlertLevelFatal || code != AlertCode(7) || got != desc {
			t.Fatalf("desc %d bytes: exact length must decode intact: %q %v", len(desc), got, err)
		}
		// A description length that claims more than the frame holds, by every shortfall.
		for short := 1; short <= len(desc)+3; short++ {
			if short > len(full) {
				break
			}
			cut := full[:len(full)-short]
			mustNotPanic(t, "DecodeAlert on a truncated frame", func() {
				_, _, _, err = c.DecodeAlert(cut)
			})
			if err == nil && len(cut) < HeaderSize+3+len(desc) {
				t.Fatalf("desc %d bytes, short by %d: truncated alert was accepted", len(desc), short)
			}
		}
		// Trailing bytes after the description are not part of it.
		if _, _, got, err := c.DecodeAlert(append(bytes.Clone(full), 0xEE, 0xEE)); err != nil || got != desc {
			t.Fatalf("trailing bytes changed the result: %q %v", got, err)
		}
	}
}

func TestDecodeRekeyAndDataMinimumLength(t *testing.T) {
	c := NewCodec()

	// A rekey or data frame carries a header and an 8-byte sequence; the ciphertext may be empty.
	rk, _ := c.EncodeRekey(9, nil)
	if len(rk) != HeaderSize+8 {
		t.Fatalf("test assumption: an empty rekey is %d bytes", len(rk))
	}
	if seq, ct, err := c.DecodeRekey(rk); err != nil || seq != 9 || len(ct) != 0 {
		t.Fatalf("minimum rekey frame must decode: %d %d %v", seq, len(ct), err)
	}
	dt, _ := c.EncodeData(9, nil)
	if seq, p, err := c.DecodeData(dt); err != nil || seq != 9 || len(p) != 0 {
		t.Fatalf("minimum data frame must decode: %d %d %v", seq, len(p), err)
	}
	for n := range len(rk) {
		mustNotPanic(t, "DecodeRekey on a short frame", func() {
			if _, _, err := c.DecodeRekey(rk[:n]); err == nil {
				t.Fatalf("rekey frame of %d bytes was accepted", n)
			}
		})
		mustNotPanic(t, "DecodeData on a short frame", func() {
			if _, _, err := c.DecodeData(dt[:n]); err == nil {
				t.Fatalf("data frame of %d bytes was accepted", n)
			}
		})
	}
}

func TestDecodeRekeyPayloadBoundaries(t *testing.T) {
	c := NewCodec()
	key := bytes.Repeat([]byte{0x5A}, 40)
	full, err := c.EncodeRekeyPayload(key, 77)
	if err != nil {
		t.Fatal(err)
	}
	if got, seq, err := c.DecodeRekeyPayload(full); err != nil || seq != 77 || !bytes.Equal(got, key) {
		t.Fatalf("exact length must decode: %v", err)
	}
	for n := range len(full) {
		mustNotPanic(t, "DecodeRekeyPayload on a short payload", func() {
			if _, _, err := c.DecodeRekeyPayload(full[:n]); err == nil {
				t.Fatalf("payload of %d bytes (full %d) was accepted", n, len(full))
			}
		})
	}
}

func TestParseDatagramHandshakeCookieBoundaries(t *testing.T) {
	h := DatagramHandshakeHeader{
		DatagramHeader: DatagramHeader{Type: DatagramFrameHandshake},
		SenderIndex:    5,
		MsgType:        MessageTypeClientHello,
		TotalLength:    0,
		Cookie:         bytes.Repeat([]byte{0xC0}, 16),
	}
	// FragLength 0 and no fragment: the cookie ends exactly at the end of the frame.
	full, err := EncodeDatagramHandshake(h, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, frag, err := ParseDatagramHandshake(full)
	if err != nil || len(frag) != 0 || !bytes.Equal(got.Cookie, h.Cookie) {
		t.Fatalf("a frame that ends exactly after its cookie must parse: %v", err)
	}
	// Every shorter frame, including those that end inside the cookie, is an error.
	for n := range len(full) {
		mustNotPanic(t, "ParseDatagramHandshake on a short frame", func() {
			if _, _, err := ParseDatagramHandshake(full[:n]); err == nil {
				t.Fatalf("frame of %d bytes (full %d) was accepted", n, len(full))
			}
		})
	}
}
