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
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"time"

	"golang.org/x/crypto/openpgp/packet"
	check "gopkg.in/check.v1"
)

type extKeypairMgrImplSuite struct{}

var _ = check.Suite(&extKeypairMgrImplSuite{})

type fakeExtKeypairMgrBackendBase struct {
	signing        extKeypairMgrSigning
	loadByName     map[string]*extKeypairMgrLoadedKey
	visitKeys      []*extKeypairMgrLoadedKey
	loadCalls      []string
	visitCalls     int
	rsaSignHandles []string
	pgpSignHandles []string
	privByHandle   map[string]*rsa.PrivateKey
}

type fakeExtKeypairMgrBackend struct {
	fakeExtKeypairMgrBackendBase
}

type fakeExtKeypairMgrBackendWithoutLookup struct {
	fakeExtKeypairMgrBackendBase
}

func (s *fakeExtKeypairMgrBackendBase) CheckFeatures() (extKeypairMgrSigning, error) {
	return s.signing, nil
}

func (s *fakeExtKeypairMgrBackend) LoadByName(name string) (*extKeypairMgrLoadedKey, error) {
	s.loadCalls = append(s.loadCalls, name)
	loaded := s.loadByName[name]
	if loaded == nil {
		return nil, &keyNotFoundError{msg: "missing key"}
	}
	return loaded, nil
}

func (s *fakeExtKeypairMgrBackendBase) Visit(consider func(loaded *extKeypairMgrLoadedKey) error) error {
	s.visitCalls++
	for _, loaded := range s.visitKeys {
		if err := consider(loaded); err != nil {
			return err
		}
	}
	return nil
}

func (s *fakeExtKeypairMgrBackendBase) RSAPKCSSign(keyHandle string, prepared []byte) ([]byte, error) {
	s.rsaSignHandles = append(s.rsaSignHandles, keyHandle)
	return rsa.SignPKCS1v15(rand.Reader, s.privByHandle[keyHandle], 0, prepared)
}

func (s *fakeExtKeypairMgrBackendBase) Sign(keyHandle string, content []byte) (*packet.Signature, error) {
	s.pgpSignHandles = append(s.pgpSignHandles, keyHandle)
	return openpgpPrivateKey{privk: packet.NewRSAPrivateKey(v1FixedTimestamp, s.privByHandle[keyHandle])}.sign(content)
}

func (s *extKeypairMgrImplSuite) newLoadedKey(c *check.C, name string, keyHandle string) (*rsa.PrivateKey, *extKeypairMgrLoadedKey) {
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	c.Assert(err, check.IsNil)
	return privKey, &extKeypairMgrLoadedKey{
		name:      name,
		keyHandle: keyHandle,
		pubKey:    RSAPublicKey(&privKey.PublicKey),
	}
}

func (s *extKeypairMgrImplSuite) TestLoadByNameCachesExportAndPrivateKey(c *check.C) {
	privKey, loaded := s.newLoadedKey(c, "default", "handle-default")
	backend := &fakeExtKeypairMgrBackend{
		fakeExtKeypairMgrBackendBase: fakeExtKeypairMgrBackendBase{
			signing: extKeypairMgrSigningRSAPKCS,
			loadByName: map[string]*extKeypairMgrLoadedKey{
				"default": loaded,
			},
			privByHandle: map[string]*rsa.PrivateKey{
				"handle-default": privKey,
			},
		},
	}

	impl, err := newExtKeypairMgrImpl(backend, "fake", func() error {
		return &keyNotFoundError{msg: "missing key"}
	})
	c.Assert(err, check.IsNil)

	key1, err := impl.GetByName("default")
	c.Assert(err, check.IsNil)
	key2, err := impl.GetByName("default")
	c.Assert(err, check.IsNil)
	exported, err := impl.Export("default")
	c.Assert(err, check.IsNil)
	expectedExport, err := EncodePublicKey(loaded.pubKey)
	c.Assert(err, check.IsNil)

	c.Check(key1, check.Equals, key2)
	c.Check(backend.loadCalls, check.DeepEquals, []string{"default"})
	c.Check(backend.visitCalls, check.Equals, 0)
	c.Check(exported, check.DeepEquals, expectedExport)
}

func (s *extKeypairMgrImplSuite) TestGetFallsBackToWalkAndCachesEntries(c *check.C) {
	privKey1, loaded1 := s.newLoadedKey(c, "default", "handle-default")
	privKey2, loaded2 := s.newLoadedKey(c, "models", "handle-models")
	backend := &fakeExtKeypairMgrBackend{
		fakeExtKeypairMgrBackendBase: fakeExtKeypairMgrBackendBase{
			signing:      extKeypairMgrSigningRSAPKCS,
			loadByName:   map[string]*extKeypairMgrLoadedKey{},
			visitKeys:    []*extKeypairMgrLoadedKey{loaded1, loaded2},
			privByHandle: map[string]*rsa.PrivateKey{"handle-default": privKey1, "handle-models": privKey2},
		},
	}

	impl, err := newExtKeypairMgrImpl(backend, "fake", func() error {
		return &keyNotFoundError{msg: "missing key"}
	})
	c.Assert(err, check.IsNil)

	key2, err := impl.Get(loaded2.pubKey.ID())
	c.Assert(err, check.IsNil)
	key1, err := impl.Get(loaded1.pubKey.ID())
	c.Assert(err, check.IsNil)
	list, err := impl.List()
	c.Assert(err, check.IsNil)

	c.Check(key2.PublicKey().ID(), check.Equals, loaded2.pubKey.ID())
	c.Check(key1.PublicKey().ID(), check.Equals, loaded1.pubKey.ID())
	c.Check(backend.visitCalls, check.Equals, 2)
	c.Check(list, check.DeepEquals, []ExternalKeyInfo{{Name: "default", ID: loaded1.pubKey.ID()}, {Name: "models", ID: loaded2.pubKey.ID()}})
}

func (s *extKeypairMgrImplSuite) TestGetByNameUsesDirectLookupFastPath(c *check.C) {
	privKey, loaded := s.newLoadedKey(c, "default", "handle-default")
	backend := &fakeExtKeypairMgrBackend{
		fakeExtKeypairMgrBackendBase: fakeExtKeypairMgrBackendBase{
			signing: extKeypairMgrSigningRSAPKCS,
			loadByName: map[string]*extKeypairMgrLoadedKey{
				"default": loaded,
			},
			visitKeys: []*extKeypairMgrLoadedKey{loaded},
			privByHandle: map[string]*rsa.PrivateKey{
				"handle-default": privKey,
			},
		},
	}

	impl, err := newExtKeypairMgrImpl(backend, "fake", func() error {
		return &keyNotFoundError{msg: "missing key"}
	})
	c.Assert(err, check.IsNil)

	_, err = impl.GetByName("default")
	c.Assert(err, check.IsNil)

	c.Check(backend.loadCalls, check.DeepEquals, []string{"default"})
	c.Check(backend.visitCalls, check.Equals, 0)
}

func (s *extKeypairMgrImplSuite) TestGetByNameFallsBackToVisitWithoutDirectLookup(c *check.C) {
	privKey, loaded := s.newLoadedKey(c, "default", "handle-default")
	backend := &fakeExtKeypairMgrBackendWithoutLookup{
		fakeExtKeypairMgrBackendBase: fakeExtKeypairMgrBackendBase{
			signing:   extKeypairMgrSigningRSAPKCS,
			visitKeys: []*extKeypairMgrLoadedKey{loaded},
			privByHandle: map[string]*rsa.PrivateKey{
				"handle-default": privKey,
			},
		},
	}

	impl, err := newExtKeypairMgrImpl(backend, "fake", func() error {
		return &keyNotFoundError{msg: "missing key"}
	})
	c.Assert(err, check.IsNil)

	priv, err := impl.GetByName("default")
	c.Assert(err, check.IsNil)
	c.Check(priv.PublicKey().ID(), check.Equals, loaded.pubKey.ID())
	c.Check(backend.visitCalls, check.Equals, 1)
}

func (s *extKeypairMgrImplSuite) TestGetByNameFallbackCachesVisitedEntry(c *check.C) {
	privKey, loaded := s.newLoadedKey(c, "default", "handle-default")
	backend := &fakeExtKeypairMgrBackendWithoutLookup{
		fakeExtKeypairMgrBackendBase: fakeExtKeypairMgrBackendBase{
			signing:   extKeypairMgrSigningRSAPKCS,
			visitKeys: []*extKeypairMgrLoadedKey{loaded},
			privByHandle: map[string]*rsa.PrivateKey{
				"handle-default": privKey,
			},
		},
	}

	impl, err := newExtKeypairMgrImpl(backend, "fake", func() error {
		return &keyNotFoundError{msg: "missing key"}
	})
	c.Assert(err, check.IsNil)

	key1, err := impl.GetByName("default")
	c.Assert(err, check.IsNil)
	exported, err := impl.Export("default")
	c.Assert(err, check.IsNil)
	key2, err := impl.GetByName("default")
	c.Assert(err, check.IsNil)
	expectedExport, err := EncodePublicKey(loaded.pubKey)
	c.Assert(err, check.IsNil)

	c.Check(key1, check.Equals, key2)
	c.Check(exported, check.DeepEquals, expectedExport)
	c.Check(backend.visitCalls, check.Equals, 1)
}

func (s *extKeypairMgrImplSuite) TestReadOpenPGPRSAPublicKey(c *check.C) {
	privKey, err := rsa.GenerateKey(rand.Reader, 1024)
	c.Assert(err, check.IsNil)

	primary := packet.NewRSAPublicKey(time.Now(), &privKey.PublicKey)
	subkey := packet.NewRSAPublicKey(time.Now(), &privKey.PublicKey)
	subkey.IsSubkey = true

	buf := new(bytes.Buffer)
	err = primary.Serialize(buf)
	c.Assert(err, check.IsNil)
	err = subkey.Serialize(buf)
	c.Assert(err, check.IsNil)

	pubKey, fingerprint, err := readOpenPGPRSAPublicKey(bytes.NewReader(buf.Bytes()))
	c.Assert(err, check.IsNil)
	c.Check(pubKey.ID(), check.Equals, RSAPublicKey(&privKey.PublicKey).ID())
	c.Check(fingerprint, check.Equals, fmt.Sprintf("%X", primary.Fingerprint))
}

func (s *extKeypairMgrImplSuite) TestGetByNameFallbackUsesConfiguredMissingKeyError(c *check.C) {
	backend := &fakeExtKeypairMgrBackendWithoutLookup{
		fakeExtKeypairMgrBackendBase: fakeExtKeypairMgrBackendBase{
			signing: extKeypairMgrSigningRSAPKCS,
		},
	}

	impl, err := newExtKeypairMgrImpl(backend, "fake", func() error {
		return &keyNotFoundError{msg: "cannot find fake key"}
	})
	c.Assert(err, check.IsNil)

	_, err = impl.GetByName("missing")
	c.Assert(err, check.ErrorMatches, `cannot find fake key`)
	c.Check(IsKeyNotFound(err), check.Equals, true)
	c.Check(backend.visitCalls, check.Equals, 1)
}

func (s *extKeypairMgrImplSuite) TestGetMissingUsesConfiguredError(c *check.C) {
	backend := &fakeExtKeypairMgrBackend{
		fakeExtKeypairMgrBackendBase: fakeExtKeypairMgrBackendBase{
			signing:      extKeypairMgrSigningRSAPKCS,
			loadByName:   map[string]*extKeypairMgrLoadedKey{},
			privByHandle: map[string]*rsa.PrivateKey{},
		},
	}

	impl, err := newExtKeypairMgrImpl(backend, "fake", func() error {
		return &keyNotFoundError{msg: "cannot find fake key"}
	})
	c.Assert(err, check.IsNil)

	_, err = impl.Get("missing-id")
	c.Assert(err, check.ErrorMatches, `cannot find fake key`)
	c.Check(IsKeyNotFound(err), check.Equals, true)
	c.Check(backend.visitCalls, check.Equals, 1)
}

func (s *extKeypairMgrImplSuite) TestRSAPKCSSigningUsesKeyHandle(c *check.C) {
	privKey, loaded := s.newLoadedKey(c, "default", "rsa-handle")
	backend := &fakeExtKeypairMgrBackend{
		fakeExtKeypairMgrBackendBase: fakeExtKeypairMgrBackendBase{
			signing: extKeypairMgrSigningRSAPKCS,
			loadByName: map[string]*extKeypairMgrLoadedKey{
				"default": loaded,
			},
			privByHandle: map[string]*rsa.PrivateKey{
				"rsa-handle": privKey,
			},
		},
	}

	impl, err := newExtKeypairMgrImpl(backend, "fake", func() error {
		return &keyNotFoundError{msg: "missing key"}
	})
	c.Assert(err, check.IsNil)

	priv, err := impl.GetByName("default")
	c.Assert(err, check.IsNil)
	sig, err := RawSignWithKey([]byte("hello"), priv)
	c.Assert(err, check.IsNil)
	err = RawVerifyWithKey([]byte("hello"), sig, priv.PublicKey())
	c.Assert(err, check.IsNil)
	c.Check(backend.rsaSignHandles, check.DeepEquals, []string{"rsa-handle"})
}

func (s *extKeypairMgrImplSuite) TestOpenPGPSigningUsesKeyHandle(c *check.C) {
	privKey, loaded := s.newLoadedKey(c, "default", "pgp-handle")
	backend := &fakeExtKeypairMgrBackend{
		fakeExtKeypairMgrBackendBase: fakeExtKeypairMgrBackendBase{
			signing: extKeypairMgrSigningOpenPGP,
			loadByName: map[string]*extKeypairMgrLoadedKey{
				"default": loaded,
			},
			privByHandle: map[string]*rsa.PrivateKey{
				"pgp-handle": privKey,
			},
		},
	}

	impl, err := newExtKeypairMgrImpl(backend, "fake", func() error {
		return &keyNotFoundError{msg: "missing key"}
	})
	c.Assert(err, check.IsNil)

	priv, err := impl.GetByName("default")
	c.Assert(err, check.IsNil)
	sig, err := RawSignWithKey([]byte("hello"), priv)
	c.Assert(err, check.IsNil)
	err = RawVerifyWithKey([]byte("hello"), sig, priv.PublicKey())
	c.Assert(err, check.IsNil)
	c.Check(backend.pgpSignHandles, check.DeepEquals, []string{"pgp-handle"})
}
