package zlog

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
)

// CheckpointSigner signs immutable segment trailers and global checkpoints.
type CheckpointSigner interface {
	KeyID() string
	Algorithm() string
	Sign(context.Context, []byte) ([]byte, error)
	PublicKeyPEM() ([]byte, error)
}

// SignatureVerifier verifies historical signatures by key identifier.
type SignatureVerifier interface {
	VerifySignature(context.Context, string, string, []byte, []byte) error
}

type Ed25519CheckpointSigner struct {
	id      string
	private ed25519.PrivateKey
}

func NewEd25519CheckpointSigner(id string, private ed25519.PrivateKey) (*Ed25519CheckpointSigner, error) {
	if id == "" {
		return nil, errors.New("zlog: signer key id is required")
	}
	if len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("zlog: invalid Ed25519 private key")
	}
	return &Ed25519CheckpointSigner{id: id, private: append(ed25519.PrivateKey(nil), private...)}, nil
}

func GenerateEd25519CheckpointSigner(id string) (*Ed25519CheckpointSigner, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return NewEd25519CheckpointSigner(id, private)
}
func (s *Ed25519CheckpointSigner) KeyID() string     { return s.id }
func (s *Ed25519CheckpointSigner) Algorithm() string { return "Ed25519" }
func (s *Ed25519CheckpointSigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	return ed25519.Sign(s.private, msg), nil
}
func (s *Ed25519CheckpointSigner) PublicKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(s.private.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
func (s *Ed25519CheckpointSigner) PrivateKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(s.private)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

type ECDSACheckpointSigner struct {
	id      string
	private *ecdsa.PrivateKey
}

func NewECDSACheckpointSigner(id string, private *ecdsa.PrivateKey) (*ECDSACheckpointSigner, error) {
	if id == "" || private == nil || private.Curve != elliptic.P256() {
		return nil, errors.New("zlog: ECDSA signer requires id and P-256 private key")
	}
	return &ECDSACheckpointSigner{id: id, private: private}, nil
}
func GenerateECDSACheckpointSigner(id string) (*ECDSACheckpointSigner, error) {
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	return NewECDSACheckpointSigner(id, k)
}
func (s *ECDSACheckpointSigner) KeyID() string     { return s.id }
func (s *ECDSACheckpointSigner) Algorithm() string { return "ECDSA-P256-SHA256" }
func (s *ECDSACheckpointSigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	h := sha256.Sum256(msg)
	r, ss, e := ecdsa.Sign(rand.Reader, s.private, h[:])
	if e != nil {
		return nil, e
	}
	// Canonical low-S encoding prevents signature malleability.
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(s.private.Params().N), 1)
	if ss.Cmp(halfOrder) > 0 {
		ss.Sub(s.private.Params().N, ss)
	}
	return marshalECDSASignature(r, ss), nil
}
func (s *ECDSACheckpointSigner) PublicKeyPEM() ([]byte, error) {
	der, e := x509.MarshalPKIXPublicKey(&s.private.PublicKey)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

type RSAPSSCheckpointSigner struct {
	id      string
	private *rsa.PrivateKey
}

func NewRSAPSSCheckpointSigner(id string, k *rsa.PrivateKey) (*RSAPSSCheckpointSigner, error) {
	if id == "" || k == nil || k.N.BitLen() < 2048 {
		return nil, errors.New("zlog: RSA-PSS signer requires id and RSA key >= 2048 bits")
	}
	if err := k.Validate(); err != nil {
		return nil, err
	}
	return &RSAPSSCheckpointSigner{id: id, private: k}, nil
}
func GenerateRSAPSSCheckpointSigner(id string, bits int) (*RSAPSSCheckpointSigner, error) {
	if bits < 2048 {
		bits = 3072
	}
	k, e := rsa.GenerateKey(rand.Reader, bits)
	if e != nil {
		return nil, e
	}
	return NewRSAPSSCheckpointSigner(id, k)
}
func (s *RSAPSSCheckpointSigner) KeyID() string     { return s.id }
func (s *RSAPSSCheckpointSigner) Algorithm() string { return "RSA-PSS-SHA256" }
func (s *RSAPSSCheckpointSigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	h := sha256.Sum256(msg)
	return rsa.SignPSS(rand.Reader, s.private, crypto.SHA256, h[:], nil)
}
func (s *RSAPSSCheckpointSigner) PublicKeyPEM() ([]byte, error) {
	der, e := x509.MarshalPKIXPublicKey(&s.private.PublicKey)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

type HMACCheckpointSigner struct {
	id  string
	key []byte
}

func NewHMACCheckpointSigner(id string, key []byte) (*HMACCheckpointSigner, error) {
	if id == "" || len(key) < 32 {
		return nil, errors.New("zlog: HMAC signer requires id and at least 32 bytes")
	}
	return &HMACCheckpointSigner{id: id, key: append([]byte(nil), key...)}, nil
}
func (s *HMACCheckpointSigner) KeyID() string     { return s.id }
func (s *HMACCheckpointSigner) Algorithm() string { return "HMAC-SHA256" }
func (s *HMACCheckpointSigner) Sign(_ context.Context, msg []byte) ([]byte, error) {
	m := hmac.New(sha256.New, s.key)
	_, _ = m.Write(msg)
	return m.Sum(nil), nil
}
func (s *HMACCheckpointSigner) PublicKeyPEM() ([]byte, error) {
	return nil, errors.New("zlog: HMAC has no public verification key")
}

// PublicKeyRegistry is concurrency-safe and supports historical key rotation.
type PublicKeyRegistry struct {
	mu   sync.RWMutex
	keys map[string]registryKey
}
type registryKey struct {
	algorithm   string
	key         any
	fingerprint [32]byte
}

func NewPublicKeyRegistry() *PublicKeyRegistry {
	return &PublicKeyRegistry{keys: make(map[string]registryKey)}
}
func (r *PublicKeyRegistry) RegisterPEM(id, algorithm string, data []byte) error {
	if id == "" {
		return errors.New("zlog: key id is required")
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return errors.New("zlog: invalid public key PEM")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}
	switch algorithm {
	case "Ed25519":
		if _, ok := key.(ed25519.PublicKey); !ok {
			return errors.New("zlog: PEM is not Ed25519")
		}
	case "ECDSA-P256-SHA256":
		k, ok := key.(*ecdsa.PublicKey)
		if !ok || k.Curve != elliptic.P256() {
			return errors.New("zlog: PEM is not ECDSA P-256")
		}
	case "RSA-PSS-SHA256":
		k, ok := key.(*rsa.PublicKey)
		if !ok || k.N.BitLen() < 2048 {
			return errors.New("zlog: PEM is not RSA >= 2048")
		}
	default:
		return fmt.Errorf("zlog: unsupported signature algorithm %q", algorithm)
	}
	fingerprint := domainHash("ZLOG-VERIFICATION-KEY-V1", []byte(algorithm), block.Bytes)
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.keys[id]; ok {
		if old.algorithm != algorithm {
			return fmt.Errorf("zlog: key id %q already registered with %s", id, old.algorithm)
		}
		if old.fingerprint != fingerprint {
			return fmt.Errorf("zlog: key id %q already identifies different key material", id)
		}
		return nil
	}
	r.keys[id] = registryKey{algorithm: algorithm, key: key, fingerprint: fingerprint}
	return nil
}
func (r *PublicKeyRegistry) RegisterHMAC(id string, key []byte) error {
	if id == "" || len(key) < 32 {
		return errors.New("zlog: HMAC key id and 32-byte key required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	fingerprint := domainHash("ZLOG-VERIFICATION-KEY-V1", []byte("HMAC-SHA256"), key)
	if old, ok := r.keys[id]; ok {
		if old.algorithm != "HMAC-SHA256" {
			return fmt.Errorf("zlog: key id %q already registered with %s", id, old.algorithm)
		}
		if old.fingerprint != fingerprint {
			return fmt.Errorf("zlog: key id %q already identifies different key material", id)
		}
		return nil
	}
	r.keys[id] = registryKey{algorithm: "HMAC-SHA256", key: append([]byte(nil), key...), fingerprint: fingerprint}
	return nil
}
func (r *PublicKeyRegistry) VerifySignature(_ context.Context, id, algorithm string, msg, sig []byte) error {
	r.mu.RLock()
	entry, ok := r.keys[id]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("zlog: unknown verification key %q", id)
	}
	if entry.algorithm != algorithm {
		return fmt.Errorf("zlog: key algorithm mismatch: have %s want %s", entry.algorithm, algorithm)
	}
	switch algorithm {
	case "Ed25519":
		if !ed25519.Verify(entry.key.(ed25519.PublicKey), msg, sig) {
			return errors.New("zlog: invalid Ed25519 signature")
		}
	case "ECDSA-P256-SHA256":
		rint, sint, err := unmarshalECDSASignature(sig)
		if err != nil {
			return err
		}
		h := sha256.Sum256(msg)
		public := entry.key.(*ecdsa.PublicKey)
		halfOrder := new(big.Int).Rsh(new(big.Int).Set(public.Params().N), 1)
		if sint.Cmp(halfOrder) > 0 || !ecdsa.Verify(public, h[:], rint, sint) {
			return errors.New("zlog: invalid ECDSA signature")
		}
	case "RSA-PSS-SHA256":
		h := sha256.Sum256(msg)
		if err := rsa.VerifyPSS(entry.key.(*rsa.PublicKey), crypto.SHA256, h[:], sig, nil); err != nil {
			return fmt.Errorf("zlog: invalid RSA-PSS signature: %w", err)
		}
	case "HMAC-SHA256":
		m := hmac.New(sha256.New, entry.key.([]byte))
		_, _ = m.Write(msg)
		if !hmac.Equal(m.Sum(nil), sig) {
			return errors.New("zlog: invalid HMAC signature")
		}
	default:
		return fmt.Errorf("zlog: unsupported signature algorithm %q", algorithm)
	}
	return nil
}

func marshalECDSASignature(r, s *big.Int) []byte {
	rb := r.Bytes()
	sb := s.Bytes()
	out := make([]byte, 4+len(rb)+len(sb))
	out[0] = byte(len(rb) >> 8)
	out[1] = byte(len(rb))
	copy(out[2:], rb)
	off := 2 + len(rb)
	out[off] = byte(len(sb) >> 8)
	out[off+1] = byte(len(sb))
	copy(out[off+2:], sb)
	return out
}
func unmarshalECDSASignature(b []byte) (*big.Int, *big.Int, error) {
	if len(b) < 4 {
		return nil, nil, errors.New("zlog: malformed ECDSA signature")
	}
	rl := int(b[0])<<8 | int(b[1])
	if rl <= 0 || 2+rl+2 > len(b) {
		return nil, nil, errors.New("zlog: malformed ECDSA signature")
	}
	off := 2 + rl
	sl := int(b[off])<<8 | int(b[off+1])
	if sl <= 0 || off+2+sl != len(b) {
		return nil, nil, errors.New("zlog: malformed ECDSA signature")
	}
	return new(big.Int).SetBytes(b[2:off]), new(big.Int).SetBytes(b[off+2:]), nil
}

func SavePrivateSigner(path string, s CheckpointSigner, perm os.FileMode) error {
	if perm == 0 {
		perm = 0600
	}
	var b []byte
	var err error
	switch x := s.(type) {
	case *Ed25519CheckpointSigner:
		b, err = x.PrivateKeyPEM()
	case *ECDSACheckpointSigner:
		var der []byte
		der, err = x509.MarshalPKCS8PrivateKey(x.private)
		if err == nil {
			b = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		}
	case *RSAPSSCheckpointSigner:
		var der []byte
		der, err = x509.MarshalPKCS8PrivateKey(x.private)
		if err == nil {
			b = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
		}
	default:
		return errors.New("zlog: signer type cannot be persisted")
	}
	if err != nil {
		return err
	}
	return writeFileAtomic(path, b, perm)
}
func LoadPrivateSigner(path, id string) (CheckpointSigner, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("zlog: invalid private key PEM")
	}
	k, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, e
	}
	switch x := k.(type) {
	case ed25519.PrivateKey:
		return NewEd25519CheckpointSigner(id, x)
	case *ecdsa.PrivateKey:
		return NewECDSACheckpointSigner(id, x)
	case *rsa.PrivateKey:
		return NewRSAPSSCheckpointSigner(id, x)
	default:
		return nil, fmt.Errorf("zlog: unsupported private key type %T", k)
	}
}

func signatureB64(b []byte) string             { return base64.RawStdEncoding.EncodeToString(b) }
func decodeSignature(s string) ([]byte, error) { return base64.RawStdEncoding.DecodeString(s) }
