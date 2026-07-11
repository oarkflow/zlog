package zlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type SecureStoreConfig struct {
	Version              string     `json:"version"`
	Dir                  string     `json:"dir"`
	StreamID             string     `json:"stream_id"`
	TenantID             string     `json:"tenant_id,omitempty"`
	DataKeyFile          string     `json:"data_key_file"`
	DataKeyID            string     `json:"data_key_id"`
	SignerPrivateKeyFile string     `json:"signer_private_key_file"`
	SignerPublicKeyFile  string     `json:"signer_public_key_file,omitempty"`
	SignerKeyID          string     `json:"signer_key_id"`
	SignatureAlgorithm   string     `json:"signature_algorithm,omitempty"`
	CheckpointEvery      uint64     `json:"checkpoint_every,omitempty"`
	SegmentMaxRecords    uint64     `json:"segment_max_records,omitempty"`
	SegmentMaxBytes      int64      `json:"segment_max_bytes,omitempty"`
	MaxRecordBytes       int        `json:"max_record_bytes,omitempty"`
	SyncPolicy           SyncPolicy `json:"sync_policy,omitempty"`
	RecoverPartial       bool       `json:"recover_partial"`
}

func (c *SecureStoreConfig) normalize(base string) error {
	if c.Version == "" {
		c.Version = "zlog.secure-config.v1"
	}
	if c.Version != "zlog.secure-config.v1" {
		return fmt.Errorf("zlog: unsupported secure config version %q", c.Version)
	}
	if c.Dir == "" || c.StreamID == "" || c.DataKeyFile == "" || c.DataKeyID == "" || c.SignerKeyID == "" || (c.SignerPrivateKeyFile == "" && c.SignerPublicKeyFile == "") {
		return errors.New("zlog: secure config requires dir, stream_id, data key and signer fields")
	}
	if !filepath.IsAbs(c.Dir) {
		c.Dir = filepath.Join(base, c.Dir)
	}
	if !filepath.IsAbs(c.DataKeyFile) {
		c.DataKeyFile = filepath.Join(base, c.DataKeyFile)
	}
	if c.SignerPrivateKeyFile != "" && !filepath.IsAbs(c.SignerPrivateKeyFile) {
		c.SignerPrivateKeyFile = filepath.Join(base, c.SignerPrivateKeyFile)
	}
	if c.SignerPublicKeyFile != "" && !filepath.IsAbs(c.SignerPublicKeyFile) {
		c.SignerPublicKeyFile = filepath.Join(base, c.SignerPublicKeyFile)
	}
	if c.SyncPolicy == "" {
		c.SyncPolicy = SyncAlways
	}
	return nil
}

func LoadSecureStoreConfig(path string) (SecureStoreConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return SecureStoreConfig{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c SecureStoreConfig
	if err = dec.Decode(&c); err != nil {
		return c, err
	}
	var extra any
	if err = dec.Decode(&extra); err == nil {
		return c, errors.New("zlog: secure config has trailing JSON")
	} else if err != io.EOF {
		return c, err
	}
	if err = c.normalize(filepath.Dir(path)); err != nil {
		return c, err
	}
	return c, nil
}
func SaveSecureStoreConfig(path string, c SecureStoreConfig) error {
	copy := c
	if err := copy.normalize(filepath.Dir(path)); err != nil {
		return err
	} // Store caller-provided relative paths rather than normalized absolute paths.
	c.Version = copy.Version
	if c.SyncPolicy == "" {
		c.SyncPolicy = copy.SyncPolicy
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return writeFileAtomic(path, b, 0600)
}
func (c SecureStoreConfig) Open(readOnly bool) (*SecureAuditStore, error) {
	key, err := LoadAuditDataKey(c.DataKeyFile)
	if err != nil {
		return nil, err
	}
	var signer CheckpointSigner
	var verifier SignatureVerifier
	if readOnly && c.SignerPublicKeyFile != "" {
		if c.SignatureAlgorithm == "" {
			return nil, errors.New("zlog: signature_algorithm is required with signer_public_key_file")
		}
		publicKey, e := os.ReadFile(c.SignerPublicKeyFile)
		if e != nil {
			return nil, e
		}
		registry := NewPublicKeyRegistry()
		if e = registry.RegisterPEM(c.SignerKeyID, c.SignatureAlgorithm, publicKey); e != nil {
			return nil, e
		}
		verifier = registry
	} else {
		if c.SignerPrivateKeyFile == "" {
			return nil, errors.New("zlog: signer private key is required for writable store")
		}
		signer, err = LoadPrivateSigner(c.SignerPrivateKeyFile, c.SignerKeyID)
		if err != nil {
			return nil, err
		}
	}
	return OpenSecureAuditStore(SecureAuditOptions{Dir: c.Dir, StreamID: c.StreamID, TenantID: c.TenantID, EncryptionKey: key, EncryptionKeyID: c.DataKeyID, Signer: signer, Verifier: verifier, CheckpointEvery: c.CheckpointEvery, SegmentMaxRecords: c.SegmentMaxRecords, SegmentMaxBytes: c.SegmentMaxBytes, MaxRecordBytes: c.MaxRecordBytes, SyncPolicy: c.SyncPolicy, RecoverPartial: c.RecoverPartial, ReadOnly: readOnly})
}
