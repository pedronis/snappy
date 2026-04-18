// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package asserts

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/openpgp/packet"
)

type extKeypairMgrSigning string

const (
	extKeypairMgrSigningRSAPKCS extKeypairMgrSigning = "RSA-PKCS"
	extKeypairMgrSigningOpenPGP extKeypairMgrSigning = "OpenPGP"
)

// extKeypairMgrBackend defines the backend contract for the shared external
// keypair manager implementation. keyHandle is the preferred backend-native
// identifier and Visit is the discovery path used for enumeration and fallback
// lookup by name when direct lookup is not available.
type extKeypairMgrBackend interface {
	// CheckFeatures validates backend support and returns the supported signing mode.
	CheckFeatures() (extKeypairMgrSigning, error)
	// Visit discovers keys and may be used for both enumeration and fallback search.
	Visit(consider func(loaded *extKeypairMgrLoadedKey) error) error
	// RSAPKCSSign signs the caller-prepared RSA-PKCS input using keyHandle.
	RSAPKCSSign(keyHandle string, prepared []byte) ([]byte, error)
	// Sign signs content directly and returns a detached OpenPGP signature packet.
	Sign(keyHandle string, content []byte) (*packet.Signature, error)
}

type extKeypairMgrDirectLookupBackend interface {
	// LoadByName resolves a user-visible name directly when the backend supports it.
	LoadByName(name string) (*extKeypairMgrLoadedKey, error)
}

type extKeypairMgrLoadedKey struct {
	name      string
	keyHandle string
	pubKey    PublicKey
}

type extKeypairMgrCachedKey struct {
	name      string
	keyHandle string
	pubKey    PublicKey
	privKey   PrivateKey
}

type extKeypairMgrConfig struct {
	signingWith string
	keyStore    string
}

type extKeypairMgrImpl struct {
	backend     extKeypairMgrBackend
	signingWith string
	keyStore    string
	signing     extKeypairMgrSigning
	nameToID    map[string]string
	// cache is keyed by public key ID and contains the loaded key information, including the private key when it has been requested.
	cache map[string]*extKeypairMgrCachedKey
}

func newExtKeypairMgrImpl(backend extKeypairMgrBackend, config extKeypairMgrConfig) (*extKeypairMgrImpl, error) {
	signing, err := backend.CheckFeatures()
	if err != nil {
		return nil, err
	}
	return &extKeypairMgrImpl{
		backend:     backend,
		signingWith: config.signingWith,
		keyStore:    config.keyStore,
		signing:     signing,
		nameToID:    make(map[string]string),
		cache:       make(map[string]*extKeypairMgrCachedKey),
	}, nil
}

func (m *extKeypairMgrImpl) keyNotFoundError() error {
	return &keyNotFoundError{msg: fmt.Sprintf("cannot find key pair in %s", m.keyStore)}
}

func (m *extKeypairMgrImpl) cacheLoadedKey(loaded *extKeypairMgrLoadedKey) (*extKeypairMgrCachedKey, error) {
	if loaded == nil {
		return nil, fmt.Errorf("internal error: missing loaded key")
	}
	if loaded.name == "" {
		return nil, fmt.Errorf("internal error: loaded key is missing a name")
	}
	if loaded.keyHandle == "" {
		return nil, fmt.Errorf("internal error: loaded key %q is missing a key handle", loaded.name)
	}
	if loaded.pubKey == nil {
		return nil, fmt.Errorf("internal error: loaded key %q is missing a public key", loaded.name)
	}
	if _, err := cryptoRSAPublicKey(loaded.pubKey); err != nil {
		return nil, fmt.Errorf("loaded key %q has invalid public key: %v", loaded.name, err)
	}

	keyID := loaded.pubKey.ID()
	entry := m.cache[keyID]
	if entry == nil {
		entry = &extKeypairMgrCachedKey{
			name:      loaded.name,
			keyHandle: loaded.keyHandle,
			pubKey:    loaded.pubKey,
		}
		m.cache[keyID] = entry
	} else {
		entry.name = loaded.name
		entry.keyHandle = loaded.keyHandle
		entry.pubKey = loaded.pubKey
	}
	m.nameToID[loaded.name] = keyID
	return entry, nil
}

func (m *extKeypairMgrImpl) loadByName(name string) (*extKeypairMgrCachedKey, error) {
	if keyID, ok := m.nameToID[name]; ok {
		if entry := m.cache[keyID]; entry != nil {
			return entry, nil
		}
	}
	if lookupBackend, ok := m.backend.(extKeypairMgrDirectLookupBackend); ok {
		loaded, err := lookupBackend.LoadByName(name)
		if err != nil {
			return nil, err
		}
		return m.cacheLoadedKey(loaded)
	}

	stop := errors.New("stop marker")
	var hit *extKeypairMgrCachedKey
	err := m.backend.Visit(func(loaded *extKeypairMgrLoadedKey) error {
		if loaded.name != name {
			return nil
		}
		entry, err := m.cacheLoadedKey(loaded)
		if err != nil {
			return err
		}
		hit = entry
		return stop
	})
	if err == stop {
		return hit, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, m.keyNotFoundError()
}

func (m *extKeypairMgrImpl) loadByID(keyID string) (*extKeypairMgrCachedKey, error) {
	if entry := m.cache[keyID]; entry != nil {
		return entry, nil
	}

	stop := errors.New("stop marker")
	var hit *extKeypairMgrCachedKey
	err := m.backend.Visit(func(loaded *extKeypairMgrLoadedKey) error {
		entry, err := m.cacheLoadedKey(loaded)
		if err != nil {
			return err
		}
		if entry.pubKey.ID() != keyID {
			return nil
		}
		hit = entry
		return stop
	})
	if err == stop {
		return hit, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, m.keyNotFoundError()
}

func (m *extKeypairMgrImpl) visitAll() ([]*extKeypairMgrCachedKey, error) {
	var entries []*extKeypairMgrCachedKey
	err := m.backend.Visit(func(loaded *extKeypairMgrLoadedKey) error {
		entry, err := m.cacheLoadedKey(loaded)
		if err != nil {
			return err
		}
		entries = append(entries, entry)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return entries, nil
}

func (m *extKeypairMgrImpl) privateKey(entry *extKeypairMgrCachedKey) PrivateKey {
	if entry.privKey != nil {
		return entry.privKey
	}
	rsaPub, err := cryptoRSAPublicKey(entry.pubKey)
	if err != nil {
		panic(err)
	}

	switch m.signing {
	case extKeypairMgrSigningRSAPKCS:
		signer := packet.NewSignerPrivateKey(v1FixedTimestamp, &extSigner{
			keyHandle: entry.keyHandle,
			publicKey: rsaPub,
			signWith:  m.backend.RSAPKCSSign,
		})
		signk := openpgpPrivateKey{privk: signer}
		entry.privKey = &extPGPPrivateKey{
			pubKey:     entry.pubKey,
			from:       m.signingWith,
			externalID: entry.keyHandle,
			bitLen:     rsaPub.N.BitLen(),
			doSign:     signk.sign,
		}
	case extKeypairMgrSigningOpenPGP:
		entry.privKey = &extPGPPrivateKey{
			pubKey:     entry.pubKey,
			from:       m.signingWith,
			externalID: entry.keyHandle,
			bitLen:     rsaPub.N.BitLen(),
			doSign: func(content []byte) (*packet.Signature, error) {
				return m.backend.Sign(entry.keyHandle, content)
			},
		}
	default:
		panic(fmt.Sprintf("internal error: unsupported signing mode %q", m.signing))
	}

	return entry.privKey
}

func (m *extKeypairMgrImpl) GetByName(name string) (PrivateKey, error) {
	entry, err := m.loadByName(name)
	if err != nil {
		return nil, err
	}
	return m.privateKey(entry), nil
}

func (m *extKeypairMgrImpl) Get(keyID string) (PrivateKey, error) {
	entry, err := m.loadByID(keyID)
	if err != nil {
		return nil, err
	}
	return m.privateKey(entry), nil
}

func (m *extKeypairMgrImpl) Export(name string) ([]byte, error) {
	entry, err := m.loadByName(name)
	if err != nil {
		return nil, err
	}
	return EncodePublicKey(entry.pubKey)
}

func (m *extKeypairMgrImpl) List() ([]ExternalKeyInfo, error) {
	entries, err := m.visitAll()
	if err != nil {
		return nil, err
	}
	res := make([]ExternalKeyInfo, len(entries))
	for i, entry := range entries {
		res[i] = ExternalKeyInfo{
			Name: entry.name,
			ID:   entry.pubKey.ID(),
		}
	}
	return res, nil
}

// see https://datatracker.ietf.org/doc/html/rfc2313 and more recently
// and more precisely about SHA-512:
// https://datatracker.ietf.org/doc/html/rfc3447#section-9.2 Notes 1.
var digestInfoSHA512Prefix = []byte{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}

type extSigner struct {
	keyHandle string
	publicKey crypto.PublicKey
	signWith  func(keyHandle string, prepared []byte) ([]byte, error)
}

func (es *extSigner) Public() crypto.PublicKey {
	return es.publicKey
}

func (es *extSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA512 {
		return nil, fmt.Errorf("unexpected pgp signature digest")
	}
	toSign := &bytes.Buffer{}
	toSign.Write(digestInfoSHA512Prefix)
	toSign.Write(digest)
	return es.signWith(es.keyHandle, toSign.Bytes())
}
