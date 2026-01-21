package metrics

import (
	"math"
	"testing"
)

func TestHistogramBasic(t *testing.T) {
	h := NewHistogram([]float64{10, 50, 100, 500})

	// Add observations
	h.Observe(5)   // bucket 0 (<=10)
	h.Observe(25)  // bucket 1 (<=50)
	h.Observe(75)  // bucket 2 (<=100)
	h.Observe(200) // bucket 3 (<=500)
	h.Observe(1000) // bucket 4 (overflow)

	if h.Count() != 5 {
		t.Errorf("expected count 5, got %d", h.Count())
	}

	expectedMean := (5.0 + 25 + 75 + 200 + 1000) / 5
	if h.Mean() != expectedMean {
		t.Errorf("expected mean %.2f, got %.2f", expectedMean, h.Mean())
	}
}

func TestHistogramSummary(t *testing.T) {
	h := NewHistogram([]float64{10, 50, 100})

	h.Observe(5)
	h.Observe(15)
	h.Observe(60)
	h.Observe(150)

	summary := h.Summary()

	if summary.Count != 4 {
		t.Errorf("expected count 4, got %d", summary.Count)
	}

	if summary.Min != 5 {
		t.Errorf("expected min 5, got %.2f", summary.Min)
	}

	if summary.Max != 150 {
		t.Errorf("expected max 150, got %.2f", summary.Max)
	}

	expectedSum := 5.0 + 15 + 60 + 150
	if summary.Sum != expectedSum {
		t.Errorf("expected sum %.2f, got %.2f", expectedSum, summary.Sum)
	}

	// Check buckets are cumulative
	// bucket[0] (<=10): 1 (value 5)
	// bucket[1] (<=50): 2 (values 5, 15)
	// bucket[2] (<=100): 3 (values 5, 15, 60)
	// bucket[3] (+Inf): 4 (all values)
	if len(summary.Buckets) != 4 {
		t.Fatalf("expected 4 buckets, got %d", len(summary.Buckets))
	}

	if summary.Buckets[0].Count != 1 {
		t.Errorf("expected bucket[0] count 1, got %d", summary.Buckets[0].Count)
	}
	if summary.Buckets[1].Count != 2 {
		t.Errorf("expected bucket[1] count 2, got %d", summary.Buckets[1].Count)
	}
	if summary.Buckets[2].Count != 3 {
		t.Errorf("expected bucket[2] count 3, got %d", summary.Buckets[2].Count)
	}
	if summary.Buckets[3].Count != 4 {
		t.Errorf("expected bucket[3] count 4, got %d", summary.Buckets[3].Count)
	}
}

func TestHistogramEmpty(t *testing.T) {
	h := NewHistogram([]float64{10, 50, 100})

	if h.Count() != 0 {
		t.Errorf("expected count 0, got %d", h.Count())
	}

	if h.Mean() != 0 {
		t.Errorf("expected mean 0, got %.2f", h.Mean())
	}

	summary := h.Summary()
	if summary.Count != 0 {
		t.Errorf("expected summary count 0, got %d", summary.Count)
	}
}

func TestHistogramReset(t *testing.T) {
	h := NewHistogram([]float64{10, 50, 100})

	h.Observe(25)
	h.Observe(75)

	if h.Count() != 2 {
		t.Fatal("observations not recorded")
	}

	h.Reset()

	if h.Count() != 0 {
		t.Errorf("expected count 0 after reset, got %d", h.Count())
	}

	summary := h.Summary()
	if summary.Count != 0 {
		t.Errorf("expected summary count 0 after reset, got %d", summary.Count)
	}
}

func TestHistogramMinMax(t *testing.T) {
	h := NewHistogram([]float64{100})

	h.Observe(50)
	h.Observe(10)
	h.Observe(75)

	summary := h.Summary()
	if summary.Min != 10 {
		t.Errorf("expected min 10, got %.2f", summary.Min)
	}
	if summary.Max != 75 {
		t.Errorf("expected max 75, got %.2f", summary.Max)
	}
}

func TestHistogramPercentiles(t *testing.T) {
	h := NewHistogram([]float64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100})

	// Add 100 values evenly distributed
	for i := 1; i <= 100; i++ {
		h.Observe(float64(i))
	}

	summary := h.Summary()

	// Check that percentiles are reasonable
	// p50 should be around 50
	if p50, ok := summary.Percentiles[0.5]; ok {
		if math.Abs(p50-50) > 15 {
			t.Errorf("p50 should be around 50, got %.2f", p50)
		}
	}

	// p90 should be around 90
	if p90, ok := summary.Percentiles[0.9]; ok {
		if math.Abs(p90-90) > 15 {
			t.Errorf("p90 should be around 90, got %.2f", p90)
		}
	}
}

func TestHistogramConcurrency(t *testing.T) {
	h := NewHistogram([]float64{10, 50, 100, 500, 1000})

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				h.Observe(float64(j))
			}
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	if h.Count() != 1000 {
		t.Errorf("expected count 1000, got %d", h.Count())
	}
}

func TestHistogramUnsortedBuckets(t *testing.T) {
	// Buckets should be sorted internally
	h := NewHistogram([]float64{100, 10, 50})

	h.Observe(5)  // should go to bucket <=10
	h.Observe(75) // should go to bucket <=100

	summary := h.Summary()

	// Buckets should be sorted: 10, 50, 100, +Inf
	if summary.Buckets[0].UpperBound != 10 {
		t.Errorf("expected first bucket bound 10, got %.2f", summary.Buckets[0].UpperBound)
	}
	if summary.Buckets[1].UpperBound != 50 {
		t.Errorf("expected second bucket bound 50, got %.2f", summary.Buckets[1].UpperBound)
	}
}
