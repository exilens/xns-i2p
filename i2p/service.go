package i2p

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	hostnameFile       = "hostname"
	privateKeysFile    = "private.dat"
	privateKeysLength  = 455
	certificateKeyType = byte(5)
	cryptoKeyType      = uint16(4)
)

type Service struct {
	PublicKey []byte
	Seed      []byte
	Address   string
	keys      []byte
}

func serviceFromSeed(seed []byte) (Service, error) {
	if len(seed) != ed25519.SeedSize {
		return Service{}, errors.New("Ed25519 seed must be 32 bytes")
	}
	private := ed25519.NewKeyFromSeed(seed)
	public := append([]byte(nil), private[32:]...)
	if err := validPublicKey(public); err != nil {
		return Service{}, err
	}

	encryptionSecret := derive(seed, 0)
	xPrivate, err := ecdh.X25519().NewPrivateKey(encryptionSecret)
	if err != nil {
		return Service{}, fmt.Errorf("derive X25519 private key: %w", err)
	}
	encryptionPublic := xPrivate.PublicKey().Bytes()
	padding := derive(seed, 1)

	keys := make([]byte, privateKeysLength)
	copy(keys[0:32], encryptionPublic)
	for offset := 32; offset < 256; offset += 32 {
		copy(keys[offset:offset+32], padding)
	}
	for offset := 256; offset < 352; offset += 32 {
		copy(keys[offset:offset+32], padding)
	}
	copy(keys[352:384], public)
	keys[384] = certificateKeyType
	binary.BigEndian.PutUint16(keys[385:387], 4)
	binary.BigEndian.PutUint16(keys[387:389], uint16(signingKeyType))
	binary.BigEndian.PutUint16(keys[389:391], cryptoKeyType)
	copy(keys[391:423], encryptionSecret)
	copy(keys[423:455], seed)

	address, err := Address(public)
	if err != nil {
		return Service{}, err
	}
	return Service{
		PublicKey: public,
		Seed:      append([]byte(nil), seed...),
		Address:   address,
		keys:      keys,
	}, nil
}

func WriteService(directory string, service Service) error {
	if err := verifyService(service); err != nil {
		return err
	}
	if err := ensureDirectory(directory); err != nil {
		return err
	}

	files := []struct {
		name string
		data []byte
	}{
		{privateKeysFile, service.keys},
		{hostnameFile, []byte(service.Address + "\n")},
	}
	for _, file := range files {
		path := filepath.Join(directory, file.name)
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("%s already exists", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}

	var written []string
	for _, file := range files {
		path := filepath.Join(directory, file.name)
		if err := writeExclusive(path, file.data, 0o600); err != nil {
			for _, created := range written {
				_ = os.Remove(created)
			}
			return err
		}
		written = append(written, path)
	}
	return nil
}

func ReadService(directory string) (Service, error) {
	keys, err := os.ReadFile(filepath.Join(directory, privateKeysFile))
	if err != nil {
		return Service{}, err
	}
	if len(keys) != privateKeysLength {
		return Service{}, fmt.Errorf("%s has an unsupported length", filepath.Join(directory, privateKeysFile))
	}
	if keys[384] != certificateKeyType ||
		binary.BigEndian.Uint16(keys[385:387]) != 4 ||
		binary.BigEndian.Uint16(keys[387:389]) != uint16(signingKeyType) ||
		binary.BigEndian.Uint16(keys[389:391]) != cryptoKeyType {
		return Service{}, errors.New("private.dat is not an XNS Ed25519/X25519 destination")
	}

	service, err := serviceFromSeed(keys[423:455])
	if err != nil {
		return Service{}, err
	}
	if subtle.ConstantTimeCompare(keys, service.keys) != 1 {
		return Service{}, errors.New("private.dat does not match its signing seed or the XNS derivation")
	}
	if raw, err := os.ReadFile(filepath.Join(directory, hostnameFile)); err == nil {
		if string(bytes.TrimSpace(raw)) != service.Address {
			return Service{}, errors.New("hostname does not match private.dat")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Service{}, err
	}
	return service, nil
}

func verifyService(service Service) error {
	expected, err := serviceFromSeed(service.Seed)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(service.PublicKey, expected.PublicKey) != 1 ||
		subtle.ConstantTimeCompare(service.keys, expected.keys) != 1 ||
		service.Address != expected.Address {
		return errors.New("service does not match its Ed25519 seed")
	}
	return nil
}

func derive(seed []byte, purpose byte) []byte {
	hash := hmac.New(sha256.New, seed)
	_, _ = hash.Write([]byte{'X', 'N', 'S', purpose})
	return hash.Sum(nil)
}

func ensureDirectory(path string) error {
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return os.MkdirAll(path, 0o700)
	case err != nil:
		return err
	case !info.IsDir():
		return errors.New("service destination is not a directory")
	default:
		return os.Chmod(path, 0o700)
	}
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpPath, path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists", path)
		}
		return err
	}
	return nil
}
