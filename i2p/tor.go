package i2p

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func ServiceFromTorDirectory(directory string) (Service, error) {
	secret, err := readTorTagged(filepath.Join(directory, torSecretFile), "ed25519v1-secret", 64)
	if err != nil {
		return Service{}, err
	}
	public, err := readTorTagged(filepath.Join(directory, torPublicFile), "ed25519v1-public", 32)
	if err != nil {
		return Service{}, err
	}
	service, err := serviceFromScalar(secret[:32])
	if err != nil {
		return Service{}, err
	}
	if subtle.ConstantTimeCompare(public, service.PublicKey) != 1 {
		return Service{}, errors.New("Tor public and secret key files do not match")
	}
	return service, nil
}

func readTorTagged(path, kind string, size int) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) != 32+size {
		return nil, fmt.Errorf("%s has an invalid length", path)
	}
	want := torTagged(kind, nil)
	if !bytes.Equal(raw[:32], want[:32]) {
		return nil, fmt.Errorf("%s has an invalid Tor key header", path)
	}
	return append([]byte(nil), raw[32:]...), nil
}

func torTagged(kind string, data []byte) []byte {
	header := make([]byte, 32)
	copy(header, "== "+kind+": type0 ==")
	return append(header, data...)
}
