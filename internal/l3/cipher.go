// Independent Linux reconstruction by ir_spoof; https://t.me/ir_spoof.
package l3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// Cipher prepends a cryptographically random 96-bit nonce to every ciphertext.
// The reference's four-random-byte prefix plus restarted counter can collide
// across instances sharing a key; using all twelve random bytes hardens nonce
// selection while preserving its explicit-nonce wire format. Random failure is
// fatal. The full 24-byte NL3X prefix is supplied as associated data.
type Cipher struct {
	aead      cipher.AEAD
	random    io.Reader
	nextNonce []byte
	sends     uint64
	failed    error
	mu        sync.Mutex
}

func NewCipher(key []byte, algorithm string, random io.Reader) (*Cipher, error) {
	algorithm, err := NormalizeAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	var aead cipher.AEAD
	if algorithm == "chacha20-poly1305" {
		aead, err = chacha20poly1305.New(key)
	} else {
		need := 32
		if algorithm == "aes-128-gcm" {
			need = 16
		}
		if len(key) != need {
			return nil, errors.New("l3: invalid AES key length")
		}
		var block cipher.Block
		block, err = aes.NewCipher(key)
		if err == nil {
			aead, err = cipher.NewGCM(block)
		}
	}
	if err != nil {
		return nil, errors.New("l3: cannot initialize packet cipher")
	}
	if random == nil {
		random = rand.Reader
	}
	c := &Cipher{aead: aead, random: random, nextNonce: make([]byte, aead.NonceSize())}
	if _, err = io.ReadFull(random, c.nextNonce); err != nil {
		return nil, errors.New("l3: nonce randomness unavailable")
	}
	return c, nil
}

func (c *Cipher) Overhead() int { return c.aead.NonceSize() + c.aead.Overhead() }

func (c *Cipher) Seal(plaintext, associated []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed != nil {
		return nil, c.failed
	}
	// Bound a sending instance to the standard random-GCM nonce usage limit.
	if c.sends >= 1<<32 {
		c.failed = errors.New("l3: encrypted packet limit reached; rotate the peer secret")
		return nil, c.failed
	}
	nonce := c.nextNonce
	if nonce == nil {
		nonce = make([]byte, c.aead.NonceSize())
		if _, err := io.ReadFull(c.random, nonce); err != nil {
			c.failed = errors.New("l3: nonce randomness unavailable")
			return nil, c.failed
		}
	}
	c.nextNonce = nil
	c.sends++
	return c.aead.Seal(nonce, nonce, plaintext, associated), nil
}

func (c *Cipher) Open(payload, associated []byte) ([]byte, error) {
	n := c.aead.NonceSize()
	if len(payload) < c.Overhead() {
		return nil, ErrFrame
	}
	value, err := c.aead.Open(nil, payload[:n], payload[n:], associated)
	if err != nil {
		return nil, ErrAuthentication
	}
	return value, nil
}
