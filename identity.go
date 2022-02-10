// Copyright 2021 Péter Szilágyi. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package threema

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/salsa20"
)

const (
	// identityLength is the length of a Threema account identifier
	identityLength = 8

	// secretLength is the length of a Threema private key (curve25519)
	secretLength = 32

	// publicLength is the length of a Threema public key (curve25519)
	publicLength = 32

	// symmetricLength is the length of a Threema symmetric encryption key.
	symmetricLength = 32

	// nonceLength is the cryptographic nonces used for message decryption
	nonceLength = 24

	// backupSaltLength is a cryptographic salt used to encrypt the identity.
	backupSaltLength = 8

	// backupSecretLength is a cryptographic key used to encrypt the identity.
	backupSecretLength = 32

	// backupChecksumLength is the number of checksum bytes in the exported identity.
	backupChecksumLength = 2

	// backupPbkdfIters is the number of iterations for deriving the password key.
	backupPbkdfIters = 100000
)

// Identity contains the Threema specific user identifier as well as the crypto
// keys associated with it.
type Identity struct {
	identity  string                         // Threema identifier (8 latter random tag)
	secretKey *[secretLength]byte            // Encryption secret key
	publicKey *[publicLength]byte            // Encryption public key
	contacts  map[string]*[publicLength]byte // Public keys of peers
}

// Identify decrypts and loads an identity exported from Threema. It is in the
// form of `XXXX-XXXX-...-XXXX` with 20 grouping of 4 characters each.
func Identify(export string, pass string) (*Identity, error) {
	// Convert the base32 encoded key into binary form
	enc, err := base32.StdEncoding.DecodeString(strings.ReplaceAll(export, "-", ""))
	if err != nil {
		return nil, err
	}
	// Sanity check that the key seems ok before decryption
	if want := backupSaltLength + identityLength + secretLength + backupChecksumLength; len(enc) != want {
		return nil, fmt.Errorf("invalid export length: have %v, want %v", len(enc), want)
	}
	key := pbkdf2.Key([]byte(pass), enc[:backupSaltLength], backupPbkdfIters, backupSecretLength, sha256.New)

	// Open the NaCl encrypted identity export (not a real NaCl box, only a single stream chunk)
	var naclNonce [nonceLength]byte
	var naclKey [backupSecretLength]byte
	copy(naclKey[:], key)

	dec := make([]byte, len(enc)-backupSaltLength)
	salsa20.XORKeyStream(dec, enc[backupSaltLength:], naclNonce[:], &naclKey)

	// Hash the decrypted identity and secret key and ensure they match the checksum
	if checksum := sha256.Sum256(dec[:identityLength+secretLength]); !bytes.Equal(checksum[:backupChecksumLength], dec[identityLength+secretLength:]) {
		return nil, errors.New("checksum verification failed")
	}
	// Decryption succeeded, reassemble the Threema identity locally
	var secretKey [secretLength]byte
	copy(secretKey[:], dec[identityLength:])

	var publicKey [publicLength]byte
	curve25519.ScalarBaseMult(&publicKey, &secretKey)

	return &Identity{
		identity:  string(dec[:identityLength]),
		secretKey: &secretKey,
		publicKey: &publicKey,
		contacts: map[string]*[publicLength]byte{
			string(dec[:identityLength]): &publicKey, // inject self, helps testing
		},
	}, nil
}

// Export generates a new Threema backup from the existing identity with the
// given secret passphrase.
func (t *Identity) Export(pass string) (string, error) {
	// Construct the plaintext identity blob
	identity := append([]byte(t.identity), t.secretKey[:]...)

	checksum := sha256.Sum256(append([]byte(t.identity), t.secretKey[:]...))
	identity = append(identity, checksum[:2]...)

	// Encrypt the identity with the given password and a random salt
	var salt [backupSaltLength]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return "", err
	}
	key := pbkdf2.Key([]byte(pass), salt[:], backupPbkdfIters, backupSecretLength, sha256.New)

	var naclNonce [nonceLength]byte
	var naclKey [backupSecretLength]byte
	copy(naclKey[:], key)

	enc := make([]byte, len(identity))
	salsa20.XORKeyStream(enc, identity, naclNonce[:], &naclKey)

	// Export the binary into the Threema ID format and return to the user
	var export string

	encoded := base32.StdEncoding.EncodeToString(append(salt[:], enc...))
	for i := 0; i < len(encoded)/4; i++ {
		export = export + encoded[i*4:(i+1)*4] + "-"
	}
	return export[:len(export)-1], nil
}

// Self retrieves the Threema ID of the loaded identity.
func (i *Identity) Self() string {
	return i.identity
}

// Trust injects a public key for a specific Threema id. Although we could
// retrieve this from the Threema REST API servers, it's up to the user to obtain
// the credentials.
//
// Hint: curl -k https://api.threema.ch/identity/XXXXXXXX
func (i *Identity) Trust(id string, pubkey string) error {
	if len(id) != identityLength {
		return fmt.Errorf("invalid Threema ID length: have %d, want %d", len(id), identityLength)
	}
	dec, err := base64.StdEncoding.DecodeString(pubkey)
	if err != nil {
		return err
	}
	if len(dec) != publicLength {
		return fmt.Errorf("invalid key length: have %d, want %d", len(dec), publicLength)
	}
	if _, ok := i.contacts[id]; ok {
		return errors.New("contact already exists")
	}
	var key [publicLength]byte
	copy(key[:], dec)

	i.contacts[id] = &key
	return nil
}
