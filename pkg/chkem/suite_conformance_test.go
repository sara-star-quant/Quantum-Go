package chkem_test

import (
	"testing"

	"github.com/sara-star-quant/quantum-go/pkg/chkem"
	"github.com/sara-star-quant/quantum-go/pkg/chkem/suitetest"
)

func TestBuiltInSuitesConform(t *testing.T) {
	for _, id := range []chkem.SuiteID{chkem.SuiteCHKEMv1, chkem.SuiteXWing} {
		s, ok := chkem.GetSuite(id)
		if !ok {
			t.Fatalf("suite %#x not registered", id)
		}
		t.Run(map[chkem.SuiteID]string{chkem.SuiteCHKEMv1: "chkem-v1", chkem.SuiteXWing: "xwing"}[id], func(t *testing.T) {
			suitetest.Run(t, s)
		})
	}
}
