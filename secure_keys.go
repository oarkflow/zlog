package zlog

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
)

func GenerateAuditDataKey() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}
func SaveAuditDataKey(path string, key []byte) error {
	if len(key) != 32 {
		return errors.New("zlog: audit data key must be 32 bytes")
	}
	return writeFileAtomic(path, []byte(hex.EncodeToString(key)+"\n"), 0600)
}
func LoadAuditDataKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(string(b))
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, errors.New("zlog: audit data key file must contain 64 hex characters")
	}
	return key, nil
}
