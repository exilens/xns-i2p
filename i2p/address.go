package i2p

import (
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"hash/crc32"
	"strings"

	"filippo.io/edwards25519"
)

const (
	addressSuffix      = ".b32.i2p"
	signingKeyType     = byte(11)
	blindedSigningType = byte(11)
)

var addressEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func Address(publicKey []byte) (string, error) {
	if err := validPublicKey(publicKey); err != nil {
		return "", err
	}

	raw := make([]byte, 35)
	raw[1] = signingKeyType
	raw[2] = blindedSigningType
	copy(raw[3:], publicKey)
	sum := crc32.ChecksumIEEE(publicKey)
	raw[0] ^= byte(sum)
	raw[1] ^= byte(sum >> 8)
	raw[2] ^= byte(sum >> 16)
	return strings.ToLower(addressEncoding.EncodeToString(raw)) + addressSuffix, nil
}

func PublicKey(address string) ([]byte, error) {
	address = strings.ToLower(strings.TrimSpace(address))
	address = strings.TrimSuffix(address, ".")
	if !strings.HasSuffix(address, addressSuffix) {
		return nil, errors.New("address must end in .b32.i2p")
	}

	label := strings.TrimSuffix(address, addressSuffix)
	if len(label) != 56 || strings.Contains(label, ".") {
		return nil, errors.New("address is not an I2P extended base32 address")
	}
	raw, err := addressEncoding.DecodeString(strings.ToUpper(label))
	if err != nil || len(raw) != 35 {
		return nil, errors.New("address has invalid base32 encoding")
	}

	public := append([]byte(nil), raw[3:]...)
	sum := crc32.ChecksumIEEE(public)
	raw[0] ^= byte(sum)
	raw[1] ^= byte(sum >> 8)
	raw[2] ^= byte(sum >> 16)
	if raw[0] != 0 || raw[1] != signingKeyType || raw[2] != blindedSigningType {
		return nil, errors.New("address is not an unauthenticated Ed25519 XNS destination")
	}
	if err := validPublicKey(public); err != nil {
		return nil, err
	}

	expected, _ := Address(public)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(address)) != 1 {
		return nil, errors.New("address checksum does not match")
	}
	return public, nil
}

func validPublicKey(publicKey []byte) error {
	if len(publicKey) != 32 {
		return errors.New("public key must be 32 bytes")
	}
	point, err := new(edwards25519.Point).SetBytes(publicKey)
	if err != nil {
		return errors.New("public key is not a valid Ed25519 point")
	}
	if point.Equal(edwards25519.NewIdentityPoint()) == 1 {
		return errors.New("public key is the Ed25519 identity point")
	}
	return nil
}
