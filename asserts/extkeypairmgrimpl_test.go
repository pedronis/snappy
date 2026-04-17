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
	"crypto/rand"
	"crypto/rsa"

	"golang.org/x/crypto/openpgp/packet"
	check "gopkg.in/check.v1"
)

type extKeypairMgrImplSuite struct{}

var _ = check.Suite(&extKeypairMgrImplSuite{})

type fakeExtKeypairMgrStrategy struct {
	signing        extKeypairMgrSigning
	publicKeys     extKeypairMgrPublicKeyFormat
	loadByName     map[string]*extKeypairMgrLoadedKey
	walkKeys       []*extKeypairMgrLoadedKey
	loadCalls      []string
	walkCalls      int
	rsaSignHandles []string
	pgpSignHandles []string
	privByHandle   map[string]*rsa.PrivateKey
}

func (s *fakeExtKeypairMgrStrategy) Features() (extKeypairMgrSigning, extKeypairMgrPublicKeyFormat, error) {
	return s.signing, s.publicKeys, nil
}

func (s *fakeExtKeypairMgrStrategy) LoadByName(name string) (*extKeypairMgrLoadedKey, error) {
	s.loadCalls = append(s.loadCalls, name)
	loaded := s.loadByName[name]
	if loaded == nil {
		return nil, &keyNotFoundError{msg: "missing key"}
	}
	return loaded, nil
}

func (s *fakeExtKeypairMgrStrategy) Walk(consider func(loaded *extKeypairMgrLoadedKey) error) error {
	s.walkCalls++
	for _, loaded := range s.walkKeys {
		if err := consider(loaded); err != nil {
			return err
		}
	}
	return nil
}

func (s *fakeExtKeypairMgrStrategy) RSAPKCSSign(keyHandle string, prepared []byte) ([]byte, error) {
	s.rsaSignHandles = append(s.rsaSignHandles, keyHandle)
	return rsa.SignPKCS1v15(rand.Reader, s.privByHandle[keyHandle], 0, prepared)
}

func (s *fakeExtKeypairMgrStrategy) Sign(keyHandle string, content []byte) (*packet.Signature, error) {
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
		rsaPub:    &privKey.PublicKey,
	}
}

func (s *extKeypairMgrImplSuite) TestRejectsUnsupportedFeatureMix(c *check.C) {
	strategy := &fakeExtKeypairMgrStrategy{
		signing:    extKeypairMgrSigningRSAPKCS,
		publicKeys: extKeypairMgrPublicKeyFormatOpenPGP,
	}

	_, err := newExtKeypairMgrImpl(strategy, "fake", func() error {
		return &keyNotFoundError{msg: "missing key"}
	})

	c.Assert(err, check.ErrorMatches, `unsupported external keypair manager feature combination: signing="RSA-PKCS" public-keys="OpenPGP"`)
}

func (s *extKeypairMgrImplSuite) TestLoadByNameCachesExportAndPrivateKey(c *check.C) {
	privKey, loaded := s.newLoadedKey(c, "default", "handle-default")
	strategy := &fakeExtKeypairMgrStrategy{
		signing:    extKeypairMgrSigningRSAPKCS,
		publicKeys: extKeypairMgrPublicKeyFormatDER,
		loadByName: map[string]*extKeypairMgrLoadedKey{
			"default": loaded,
		},
		privByHandle: map[string]*rsa.PrivateKey{
			"handle-default": privKey,
		},
	}

	impl, err := newExtKeypairMgrImpl(strategy, "fake", func() error {
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
	c.Check(strategy.loadCalls, check.DeepEquals, []string{"default"})
	c.Check(strategy.walkCalls, check.Equals, 0)
	c.Check(exported, check.DeepEquals, expectedExport)
}

func (s *extKeypairMgrImplSuite) TestGetFallsBackToWalkAndCachesEntries(c *check.C) {
	privKey1, loaded1 := s.newLoadedKey(c, "default", "handle-default")
	privKey2, loaded2 := s.newLoadedKey(c, "models", "handle-models")
	strategy := &fakeExtKeypairMgrStrategy{
		signing:      extKeypairMgrSigningRSAPKCS,
		publicKeys:   extKeypairMgrPublicKeyFormatDER,
		loadByName:   map[string]*extKeypairMgrLoadedKey{},
		walkKeys:     []*extKeypairMgrLoadedKey{loaded1, loaded2},
		privByHandle: map[string]*rsa.PrivateKey{"handle-default": privKey1, "handle-models": privKey2},
	}

	impl, err := newExtKeypairMgrImpl(strategy, "fake", func() error {
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
	c.Check(strategy.walkCalls, check.Equals, 2)
	c.Check(list, check.DeepEquals, []ExternalKeyInfo{{Name: "default", ID: loaded1.pubKey.ID()}, {Name: "models", ID: loaded2.pubKey.ID()}})
}

func (s *extKeypairMgrImplSuite) TestGetMissingUsesConfiguredError(c *check.C) {
	strategy := &fakeExtKeypairMgrStrategy{
		signing:      extKeypairMgrSigningRSAPKCS,
		publicKeys:   extKeypairMgrPublicKeyFormatDER,
		loadByName:   map[string]*extKeypairMgrLoadedKey{},
		privByHandle: map[string]*rsa.PrivateKey{},
	}

	impl, err := newExtKeypairMgrImpl(strategy, "fake", func() error {
		return &keyNotFoundError{msg: "cannot find fake key"}
	})
	c.Assert(err, check.IsNil)

	_, err = impl.Get("missing-id")
	c.Assert(err, check.ErrorMatches, `cannot find fake key`)
	c.Check(IsKeyNotFound(err), check.Equals, true)
	c.Check(strategy.walkCalls, check.Equals, 1)
}

func (s *extKeypairMgrImplSuite) TestRSAPKCSSigningUsesKeyHandle(c *check.C) {
	privKey, loaded := s.newLoadedKey(c, "default", "rsa-handle")
	strategy := &fakeExtKeypairMgrStrategy{
		signing:    extKeypairMgrSigningRSAPKCS,
		publicKeys: extKeypairMgrPublicKeyFormatDER,
		loadByName: map[string]*extKeypairMgrLoadedKey{
			"default": loaded,
		},
		privByHandle: map[string]*rsa.PrivateKey{
			"rsa-handle": privKey,
		},
	}

	impl, err := newExtKeypairMgrImpl(strategy, "fake", func() error {
		return &keyNotFoundError{msg: "missing key"}
	})
	c.Assert(err, check.IsNil)

	priv, err := impl.GetByName("default")
	c.Assert(err, check.IsNil)
	sig, err := RawSignWithKey([]byte("hello"), priv)
	c.Assert(err, check.IsNil)
	err = RawVerifyWithKey([]byte("hello"), sig, priv.PublicKey())
	c.Assert(err, check.IsNil)
	c.Check(strategy.rsaSignHandles, check.DeepEquals, []string{"rsa-handle"})
}

func (s *extKeypairMgrImplSuite) TestOpenPGPSigningUsesKeyHandle(c *check.C) {
	privKey, loaded := s.newLoadedKey(c, "default", "pgp-handle")
	strategy := &fakeExtKeypairMgrStrategy{
		signing:    extKeypairMgrSigningOpenPGP,
		publicKeys: extKeypairMgrPublicKeyFormatOpenPGP,
		loadByName: map[string]*extKeypairMgrLoadedKey{
			"default": loaded,
		},
		privByHandle: map[string]*rsa.PrivateKey{
			"pgp-handle": privKey,
		},
	}

	impl, err := newExtKeypairMgrImpl(strategy, "fake", func() error {
		return &keyNotFoundError{msg: "missing key"}
	})
	c.Assert(err, check.IsNil)

	priv, err := impl.GetByName("default")
	c.Assert(err, check.IsNil)
	sig, err := RawSignWithKey([]byte("hello"), priv)
	c.Assert(err, check.IsNil)
	err = RawVerifyWithKey([]byte("hello"), sig, priv.PublicKey())
	c.Assert(err, check.IsNil)
	c.Check(strategy.pgpSignHandles, check.DeepEquals, []string{"pgp-handle"})
}
