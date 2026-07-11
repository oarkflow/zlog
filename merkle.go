package zlog

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

var emptyMerkleRoot = domainHash("ZLOG-MERKLE-EMPTY-V1")

func merkleNode(left, right [32]byte) [32]byte {
	return domainHash("ZLOG-MERKLE-NODE-V1", left[:], right[:])
}

// MerkleTree is an append-only, concurrency-safe tree over pre-hashed leaves.
type MerkleTree struct {
	mu     sync.RWMutex
	leaves [][32]byte
}

func NewMerkleTree() *MerkleTree { return &MerkleTree{} }
func (t *MerkleTree) Append(leaf [32]byte) uint64 {
	t.mu.Lock()
	idx := uint64(len(t.leaves))
	t.leaves = append(t.leaves, leaf)
	t.mu.Unlock()
	return idx
}
func (t *MerkleTree) Size() uint64 {
	t.mu.RLock()
	n := len(t.leaves)
	t.mu.RUnlock()
	return uint64(n)
}
func (t *MerkleTree) Root() [32]byte {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return merkleRoot(t.leaves)
}
func (t *MerkleTree) RootAt(size uint64) ([32]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if size > uint64(len(t.leaves)) {
		return [32]byte{}, fmt.Errorf("zlog: tree size %d exceeds %d", size, len(t.leaves))
	}
	return merkleRoot(t.leaves[:size]), nil
}
func (t *MerkleTree) Inclusion(index, size uint64) ([][32]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if size == 0 || size > uint64(len(t.leaves)) || index >= size {
		return nil, fmt.Errorf("zlog: invalid inclusion index=%d size=%d", index, size)
	}
	return inclusionPath(t.leaves[:size], int(index)), nil
}
func (t *MerkleTree) Consistency(first, second uint64) ([][32]byte, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if first == 0 || first > second || second > uint64(len(t.leaves)) {
		return nil, fmt.Errorf("zlog: invalid consistency sizes %d -> %d", first, second)
	}
	if first == second {
		return nil, nil
	}
	return consistencySubproof(t.leaves[:second], int(first), true), nil
}

func merkleRoot(leaves [][32]byte) [32]byte {
	switch len(leaves) {
	case 0:
		return emptyMerkleRoot
	case 1:
		return leaves[0]
	}
	k := largestPowerOfTwoLessThan(len(leaves))
	left := merkleRoot(leaves[:k])
	right := merkleRoot(leaves[k:])
	return merkleNode(left, right)
}
func largestPowerOfTwoLessThan(n int) int {
	if n < 2 {
		return 0
	}
	k := 1
	for (k << 1) < n {
		k <<= 1
	}
	return k
}
func inclusionPath(leaves [][32]byte, index int) [][32]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := largestPowerOfTwoLessThan(len(leaves))
	if index < k {
		return append(inclusionPath(leaves[:k], index), merkleRoot(leaves[k:]))
	}
	return append(inclusionPath(leaves[k:], index-k), merkleRoot(leaves[:k]))
}
func consistencySubproof(leaves [][32]byte, m int, complete bool) [][32]byte {
	n := len(leaves)
	if m == n {
		if complete {
			return nil
		}
		return [][32]byte{merkleRoot(leaves)}
	}
	k := largestPowerOfTwoLessThan(n)
	if m <= k {
		return append(consistencySubproof(leaves[:k], m, complete), merkleRoot(leaves[k:]))
	}
	return append(consistencySubproof(leaves[k:], m-k, false), merkleRoot(leaves[:k]))
}

func VerifyInclusionProof(p InclusionProof) error {
	if p.TreeSize == 0 || p.LeafIndex >= p.TreeSize {
		return ErrInvalidProof
	}
	leaf, err := decodeHash32(p.LeafHash)
	if err != nil {
		return err
	}
	root, err := decodeHash32(p.RootHash)
	if err != nil {
		return err
	}
	fn := p.LeafIndex
	sn := p.TreeSize - 1
	calc := leaf
	for _, hs := range p.AuditPath {
		h, err := decodeHash32(hs)
		if err != nil {
			return err
		}
		if fn&1 == 1 || fn == sn {
			calc = merkleNode(h, calc)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			calc = merkleNode(calc, h)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || subtle.ConstantTimeCompare(calc[:], root[:]) != 1 {
		return ErrInvalidProof
	}
	return nil
}

func VerifyConsistencyProof(p ConsistencyProof) error {
	if p.FirstSize == 0 || p.FirstSize > p.SecondSize {
		return ErrInvalidProof
	}
	first, err := decodeHash32(p.FirstRoot)
	if err != nil {
		return err
	}
	second, err := decodeHash32(p.SecondRoot)
	if err != nil {
		return err
	}
	if p.FirstSize == p.SecondSize {
		if len(p.Path) != 0 || subtle.ConstantTimeCompare(first[:], second[:]) != 1 {
			return ErrInvalidProof
		}
		return nil
	}
	fn := p.FirstSize - 1
	sn := p.SecondSize - 1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	var fr, sr [32]byte
	pos := 0
	if fn == 0 {
		fr = first
		sr = first
	} else {
		if len(p.Path) == 0 {
			return ErrInvalidProof
		}
		h, e := decodeHash32(p.Path[0])
		if e != nil {
			return e
		}
		fr = h
		sr = h
		pos = 1
	}
	for ; pos < len(p.Path); pos++ {
		if sn == 0 {
			return ErrInvalidProof
		}
		h, e := decodeHash32(p.Path[pos])
		if e != nil {
			return e
		}
		if fn&1 == 1 || fn == sn {
			fr = merkleNode(h, fr)
			sr = merkleNode(h, sr)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = merkleNode(sr, h)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 || subtle.ConstantTimeCompare(fr[:], first[:]) != 1 || subtle.ConstantTimeCompare(sr[:], second[:]) != 1 {
		return ErrInvalidProof
	}
	return nil
}

func hashesToStrings(path [][32]byte) []string {
	out := make([]string, len(path))
	for i, h := range path {
		out[i] = hex.EncodeToString(h[:])
	}
	return out
}
func stringsToHashes(path []string) ([][32]byte, error) {
	out := make([][32]byte, len(path))
	for i, s := range path {
		h, e := decodeHash32(s)
		if e != nil {
			return nil, e
		}
		out[i] = h
	}
	return out, nil
}

func mustHash32(s string) [32]byte {
	h, e := decodeHash32(s)
	if e != nil {
		panic(e)
	}
	return h
}

var _ = errors.Is
