package metrics

import (
	"math"
	"sort"
	"sync"
)

// Histogram tracks the distribution of values across predefined buckets.
// Thread-safe for concurrent use.
type Histogram struct {
	mu      sync.RWMutex
	buckets []float64 // Upper bounds (exclusive)
	counts  []uint64  // Count per bucket
	sum     float64   // Sum of all observed values
	count   uint64    // Total count of observations
	min     float64   // Minimum observed value
	max     float64   // Maximum observed value
}

// NewHistogram creates a histogram with the given bucket boundaries.
// Buckets should be sorted in ascending order.
func NewHistogram(buckets []float64) *Histogram {
	// Make a copy and sort
	b := make([]float64, len(buckets))
	copy(b, buckets)
	sort.Float64s(b)

	return &Histogram{
		buckets: b,
		counts:  make([]uint64, len(b)+1), // +1 for overflow bucket
		min:     math.MaxFloat64,
		max:     -math.MaxFloat64,
	}
}

// Observe records a value in the histogram.
func (h *Histogram) Observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Find bucket
	idx := sort.SearchFloat64s(h.buckets, v)
	h.counts[idx]++

	// Update stats
	h.sum += v
	h.count++
	if v < h.min {
		h.min = v
	}
	if v > h.max {
		h.max = v
	}
}

// HistogramSummary contains summarized histogram data.
type HistogramSummary struct {
	Count   uint64             `json:"count"`
	Sum     float64            `json:"sum"`
	Min     float64            `json:"min"`
	Max     float64            `json:"max"`
	Mean    float64            `json:"mean"`
	Buckets []BucketCount      `json:"buckets"`
	Percentiles map[float64]float64 `json:"percentiles,omitempty"`
}

// BucketCount represents a histogram bucket with its upper bound and count.
type BucketCount struct {
	UpperBound float64 `json:"le"`    // Upper bound (less than or equal)
	Count      uint64  `json:"count"` // Cumulative count
}

// Summary returns a summary of the histogram.
func (h *Histogram) Summary() HistogramSummary {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if h.count == 0 {
		return HistogramSummary{
			Buckets: make([]BucketCount, 0),
			Percentiles: make(map[float64]float64),
		}
	}

	// Build cumulative bucket counts
	buckets := make([]BucketCount, len(h.buckets)+1)
	var cumulative uint64
	for i, bound := range h.buckets {
		cumulative += h.counts[i]
		buckets[i] = BucketCount{
			UpperBound: bound,
			Count:      cumulative,
		}
	}
	// Overflow bucket (+Inf)
	cumulative += h.counts[len(h.buckets)]
	buckets[len(h.buckets)] = BucketCount{
		UpperBound: math.Inf(1),
		Count:      cumulative,
	}

	// Calculate percentiles
	percentiles := h.calculatePercentiles([]float64{0.5, 0.9, 0.95, 0.99})

	return HistogramSummary{
		Count:       h.count,
		Sum:         h.sum,
		Min:         h.min,
		Max:         h.max,
		Mean:        h.sum / float64(h.count),
		Buckets:     buckets,
		Percentiles: percentiles,
	}
}

// calculatePercentiles estimates percentiles from histogram buckets.
// Uses linear interpolation between bucket boundaries.
func (h *Histogram) calculatePercentiles(ps []float64) map[float64]float64 {
	result := make(map[float64]float64, len(ps))

	if h.count == 0 {
		return result
	}

	for _, p := range ps {
		rank := p * float64(h.count)
		var cumulative uint64

		for i, c := range h.counts {
			cumulative += c
			if float64(cumulative) >= rank {
				if i == 0 {
					// First bucket
					result[p] = h.buckets[0] / 2
				} else if i >= len(h.buckets) {
					// Overflow bucket - use max
					result[p] = h.max
				} else {
					// Linear interpolation
					lower := h.buckets[i-1]
					upper := h.buckets[i]
					prevCumulative := cumulative - c
					fraction := (rank - float64(prevCumulative)) / float64(c)
					result[p] = lower + fraction*(upper-lower)
				}
				break
			}
		}
	}

	return result
}

// Reset clears all histogram data.
func (h *Histogram) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for i := range h.counts {
		h.counts[i] = 0
	}
	h.sum = 0
	h.count = 0
	h.min = math.MaxFloat64
	h.max = -math.MaxFloat64
}

// Count returns the total number of observations.
func (h *Histogram) Count() uint64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.count
}

// Mean returns the mean of all observations.
func (h *Histogram) Mean() float64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.count == 0 {
		return 0
	}
	return h.sum / float64(h.count)
}
