package tunnel

// SecurityClass names a kind of local security signal. The set grows by adding values, so an
// implementation of SecurityObserver must ignore a class it does not know.
type SecurityClass uint8

const (
	// SecurityPinMismatch: a client that pins the server key could not complete the
	// handshake with it. Causes include a rotated server key.
	SecurityPinMismatch SecurityClass = iota + 1
	// SecurityDowngrade: the peer chose a KEM suite this endpoint did not offer, or sent a
	// second HelloRetryRequest.
	SecurityDowngrade
	// SecurityReplay: a stream record arrived with a sequence number already seen.
	SecurityReplay
)

// SecurityConfidence says how sure the endpoint is that the event is what its class says,
// judged from the evidence at the point it was raised. It is not a measure of intent: a
// High pin mismatch can still be a key rotation nobody announced.
type SecurityConfidence uint8

const (
	SecurityLow SecurityConfidence = iota + 1
	SecurityMedium
	SecurityHigh
)

// SecurityClasses lists every class in a stable order.
func SecurityClasses() []SecurityClass {
	return []SecurityClass{SecurityPinMismatch, SecurityDowngrade, SecurityReplay}
}

// SecurityConfidences lists every confidence level, lowest first.
func SecurityConfidences() []SecurityConfidence {
	return []SecurityConfidence{SecurityLow, SecurityMedium, SecurityHigh}
}

// String returns the stable label used in metrics and logs.
func (c SecurityClass) String() string {
	switch c {
	case SecurityPinMismatch:
		return "pin_mismatch"
	case SecurityDowngrade:
		return "downgrade"
	case SecurityReplay:
		return "replay"
	}
	return "unknown"
}

// String returns the stable label used in metrics and logs.
func (c SecurityConfidence) String() string {
	switch c {
	case SecurityLow:
		return "low"
	case SecurityMedium:
		return "medium"
	case SecurityHigh:
		return "high"
	}
	return "unknown"
}

// SecurityEvent is one local signal. It stays on this host: nothing is sent to the peer, so a
// prober learns nothing from it. It carries no address or identity.
type SecurityEvent struct {
	Class      SecurityClass
	Confidence SecurityConfidence
}

// SecurityObserver is an optional extension of Observer. When the session's Observer also
// implements it, the session reports security events to it. Callbacks run on the
// connection's goroutine, so an implementation must not block.
type SecurityObserver interface {
	OnSecurityEvent(SecurityEvent)
}

// reportSecurity hands an event to the observer when it listens for them.
func (s *Session) reportSecurity(class SecurityClass, confidence SecurityConfidence) {
	if so, ok := s.observer.(SecurityObserver); ok {
		so.OnSecurityEvent(SecurityEvent{Class: class, Confidence: confidence})
	}
}
