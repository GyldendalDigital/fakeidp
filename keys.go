package fakeidp

import (
	crypto_rand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // for thumbprint-ish kid
	"crypto/x509"
	"encoding/pem"
	"time"
)

type KeyPair struct {
	Private *rsa.PrivateKey
	Public  *rsa.PublicKey
	KID     string
	Added   time.Time
}

type JWK struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func newKeyPair() KeyPair {
	priv, err := rsa.GenerateKey(crypto_rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	pub := &priv.PublicKey

	// Make a stable short kid from the public modulus (NOT spec thumbprint; good enough for tests)
	nBytes := pub.N.Bytes()
	sum := sha1.Sum(nBytes)
	kid := b64url(sum[:8])
	return KeyPair{Private: priv, Public: pub, KID: kid, Added: time.Now()}
}

func (s *Server) currentKey() KeyPair {
	s.keysMu.RLock()
	defer s.keysMu.RUnlock()
	return s.keys[0]
}

func (s *Server) keyByKID(kid string) (KeyPair, bool) {
	s.keysMu.RLock()
	defer s.keysMu.RUnlock()
	for _, k := range s.keys {
		if k.KID == kid {
			return k, true
		}
	}
	return KeyPair{}, false
}

// JWKS returns the currently published key set.
func (s *Server) JWKS() JWKS {
	s.keysMu.RLock()
	defer s.keysMu.RUnlock()
	js := JWKS{Keys: make([]JWK, 0, len(s.keys))}
	for _, k := range s.keys {
		js.Keys = append(js.Keys, JWK{
			Kty: "RSA",
			N:   b64url(k.Public.N.Bytes()),
			E:   b64url(bigEndianUint(k.Public.E)),
			Alg: "RS256",
			Use: "sig",
			Kid: k.KID,
		})
	}
	return js
}

func bigEndianUint(v int) []byte {
	// for exponent 65537 -> 0x01 0x00 0x01
	if v == 0 {
		return []byte{0}
	}
	var bytes []byte
	for v > 0 {
		bytes = append([]byte{byte(v & 0xff)}, bytes...)
		v >>= 8
	}
	return bytes
}

// RotateKeys generates a new signing key, makes it current, and drops the
// oldest keys beyond the configured keep count. Exposed so tests can drive
// rotation deterministically instead of waiting on the timer.
func (s *Server) RotateKeys() KeyPair {
	k := newKeyPair()
	s.keysMu.Lock()
	s.keys = append([]KeyPair{k}, s.keys...)
	if len(s.keys) > s.keyKeep {
		s.keys = s.keys[:s.keyKeep]
	}
	total := len(s.keys)
	s.keysMu.Unlock()
	s.logger.Info("Rotated keys", "new_kid", k.KID, "total_keys", total)
	return k
}

// CurrentKeyPEM returns the kid and PKCS#1 PEM encoding of the current
// signing key. Only useful for debugging; this is a fake after all.
func (s *Server) CurrentKeyPEM() (kid, pemStr string) {
	k := s.currentKey()
	b := x509.MarshalPKCS1PrivateKey(k.Private)
	p := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}
	return k.KID, string(pem.EncodeToMemory(p))
}

func (s *Server) rotateKeysLoop() {
	defer close(s.done)
	t := time.NewTicker(s.keyRotate)
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.RotateKeys()
		}
	}
}
