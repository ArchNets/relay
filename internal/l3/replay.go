// Independent Linux reconstruction by ir_spoof; https://t.me/ir_spoof.
package l3

import "sync"

const ReplayWindowSize = 8192

// ReplayWindow accepts bounded out-of-order records once each. The reference
// type contains 128 uint64 bitmap words, covering an 8192-record history.
type ReplayWindow struct {
	mu      sync.Mutex
	highest uint64
	bits    [ReplayWindowSize / 64]uint64
}

func (r *ReplayWindow) Accept(sequence uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sequence == 0 {
		return false
	}
	if sequence > r.highest {
		delta := sequence - r.highest
		if delta >= ReplayWindowSize {
			clear(r.bits[:])
		} else {
			for n := uint64(1); n <= delta; n++ {
				i := (r.highest + n) % ReplayWindowSize
				r.bits[i/64] &^= uint64(1) << (i % 64)
			}
		}
		r.highest = sequence
	} else if r.highest-sequence >= ReplayWindowSize {
		return false
	}
	i := sequence % ReplayWindowSize
	mask := uint64(1) << (i % 64)
	if r.bits[i/64]&mask != 0 {
		return false
	}
	r.bits[i/64] |= mask
	return true
}
