package tunnel

import (
	"github.com/sara-star-quant/quantum-go/pkg/chkem"

	qerrors "github.com/sara-star-quant/quantum-go/internal/errors"
)

// kemPolicy restricts the KEM suites an endpoint offers and accepts for the ephemeral key
// exchange. The zero value allows every supported suite. The static-key suite of a pin or a
// server identity is a separate choice and is not subject to it.
type kemPolicy []chkem.SuiteID

// supported returns the supported suites the policy allows, in the registry's preference order.
func (p kemPolicy) supported() []chkem.SuiteID {
	all := chkem.SupportedSuites()
	if len(p) == 0 {
		return all
	}
	out := make([]chkem.SuiteID, 0, len(all))
	for _, id := range all {
		for _, allowed := range p {
			if id == allowed {
				out = append(out, id)
				break
			}
		}
	}
	return out
}

// validate rejects a non-empty policy that allows no supported suite, so a typo or a FIPS
// filter cannot leave an endpoint that can negotiate nothing.
func (p kemPolicy) validate() error {
	if len(p) > 0 && len(p.supported()) == 0 {
		return qerrors.ErrUnsupportedKEMSuite
	}
	return nil
}

// ids returns the allowed suites as wire ids, for the ClientHello supported-suite list.
func (p kemPolicy) ids() []uint16 {
	ids := p.supported()
	out := make([]uint16, len(ids))
	for i, id := range ids {
		out[i] = uint16(id)
	}
	return out
}

// offered reports whether wireID is a suite this endpoint would have advertised, so a
// HelloRetryRequest cannot steer a client to a suite it never offered.
func (p kemPolicy) offered(wireID uint16) bool {
	for _, id := range p.supported() {
		if uint16(id) == wireID {
			return true
		}
	}
	return false
}

// resolve returns the suite for a wire id, or an error if this endpoint would not offer it.
func (p kemPolicy) resolve(wireID uint16) (chkem.Suite, error) {
	suite, ok := chkem.GetSuite(chkem.SuiteID(wireID))
	if !ok || !p.offered(wireID) {
		return nil, qerrors.ErrUnsupportedKEMSuite
	}
	return suite, nil
}

// mutual picks the allowed suite, in this endpoint's preference order, that also appears in
// the peer's list, or false when there is no overlap.
func (p kemPolicy) mutual(peer []uint16) (chkem.SuiteID, bool) {
	for _, local := range p.supported() {
		for _, offered := range peer {
			if uint16(local) == offered {
				return local, true
			}
		}
	}
	return 0, false
}

// initiator resolves the configured starting suite. 0 means the first allowed suite, which is
// CH-KEM-v1 unless the policy excludes it. Any other id must be one the policy allows.
func (p kemPolicy) initiator(id chkem.SuiteID) (chkem.Suite, error) {
	if id == 0 {
		if len(p) == 0 {
			return chkem.DefaultSuite(), nil
		}
		allowed := p.supported()
		if len(allowed) == 0 {
			return nil, qerrors.ErrUnsupportedKEMSuite
		}
		id = allowed[0]
	}
	return p.resolve(uint16(id))
}
