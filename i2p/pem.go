package i2p

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

func ServiceFromPEM(path string) (Service, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Service{}, err
	}
	block, rest := pem.Decode(raw)
	if block == nil {
		return Service{}, errors.New("private key is not PEM encoded")
	}
	if len(rest) != 0 {
		return Service{}, errors.New("private key PEM contains trailing data")
	}
	if x509.IsEncryptedPEMBlock(block) {
		return Service{}, errors.New("encrypted PEM files are unsupported")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return Service{}, fmt.Errorf("parse PKCS#8 private key: %w", err)
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(private) != ed25519.PrivateKeySize {
		return Service{}, errors.New("private key is not Ed25519")
	}
	return serviceFromSeed(private.Seed())
}
