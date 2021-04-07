// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2021 Canonical Ltd
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

package daemon_test

import (
	//"fmt"

	"bytes"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/netonboard"
)

var _ = Suite(&onboardSpikeSuite{})

type onboardSpikeSuite struct {
	apiBaseSuite
}

func (s *onboardSpikeSuite) TestGetNotYetOnboarded(c *C) {
	s.daemon(c)

	req, err := http.NewRequest("GET", "/v2/onboarding", nil)
	c.Assert(err, IsNil)

	rsp := s.jsonReq(c, req, nil)
	c.Assert(rsp.Status, Equals, 200)
	info := rsp.Result.(*netonboard.OnboardInfo)
	c.Check(info.Onboarded, Equals, false)
	c.Check(info.InProgress, Equals, false)
}

func (s *onboardSpikeSuite) TestGenerateSecrets(c *C) {
	s.daemon(c)

	req, err := http.NewRequest("GET", "/v2/onboarding/secrets", nil)
	c.Assert(err, IsNil)

	rsp := s.jsonReq(c, req, nil)
	c.Assert(rsp.Status, Equals, 200)
	sec := rsp.Result.(*netonboard.OnboardSecrets)
	c.Check(sec.Secret, HasLen, 32)
	c.Check(sec.DeviceKey.Key, FitsTypeOf, &ecdsa.PublicKey{})

	rsp = s.jsonReq(c, req, nil)
	c.Assert(rsp.Status, Equals, 200)
	sec1 := rsp.Result.(*netonboard.OnboardSecrets)
	tmb, err := sec.DeviceKey.Thumbprint(crypto.SHA256)
	c.Assert(err, IsNil)
	tmb1, err := sec1.DeviceKey.Thumbprint(crypto.SHA256)
	c.Assert(err, IsNil)
	c.Check(tmb1, DeepEquals, tmb)
}

func (s *onboardSpikeSuite) TestSecretsRootOnly(c *C) {
	s.daemon(c)

	req, err := http.NewRequest("GET", "/v2/onboarding/secrets", nil)
	c.Assert(err, IsNil)

	req.RemoteAddr = "pid=100;uid=1000;socket=;"
	rec := httptest.NewRecorder()
	s.serveHTTP(c, rec, req)
	c.Assert(rec.Code, Equals, 401)
}

func (s *onboardSpikeSuite) TestSessionStartTooEarly(c *C) {
	d := s.daemon(c)

	// not seeeded
	st := d.Overlord().State()
	st.Lock()
	st.Set("seeded", nil)
	st.Unlock()

	act := netonboard.OnboardSessionAction{
		Action: "start",
	}
	b, err := json.Marshal(act)
	c.Assert(err, IsNil)
	req, err := http.NewRequest("POST", "/v2/onboarding/session", bytes.NewReader(b))
	c.Assert(err, IsNil)

	rsp := s.jsonReq(c, req, nil)
	c.Check(rsp.Status, Equals, 409)
}

func (s *onboardSpikeSuite) TestSessionStart(c *C) {
	s.daemon(c)

	// generate secrets
	req, err := http.NewRequest("GET", "/v2/onboarding/secrets", nil)
	c.Assert(err, IsNil)
	rsp := s.jsonReq(c, req, nil)
	c.Assert(rsp.Status, Equals, 200)
	secrets := rsp.Result.(*netonboard.OnboardSecrets)

	cftor := &netonboard.Configurator{}
	err = cftor.SetOnboardingSecret(secrets.Secret)
	c.Assert(err, IsNil)

	hello, err := cftor.Hello()
	c.Assert(err, IsNil)

	act := netonboard.OnboardSessionAction{
		Action: "start",
		Msg:    hello,
		// XXX features/facets
	}
	b, err := json.Marshal(act)
	c.Assert(err, IsNil)
	req, err = http.NewRequest("POST", "/v2/onboarding/session", bytes.NewReader(b))
	c.Assert(err, IsNil)

	rsp = s.jsonReq(c, req, nil)
	c.Assert(rsp.Status, Equals, 200)
	sessRsp, ok := rsp.Result.(*netonboard.OnboardSessionResponse)
	c.Assert(ok, Equals, true)
	c.Check(sessRsp.MsgType, Equals, "device")
	// message would be accepted
	err = cftor.RcvDevice(sessRsp.Msg)
	c.Check(err, IsNil)

	// check state change
	req, err = http.NewRequest("GET", "/v2/onboarding", nil)
	c.Assert(err, IsNil)
	rsp = s.jsonReq(c, req, nil)
	c.Assert(rsp.Status, Equals, 200)
	info := rsp.Result.(*netonboard.OnboardInfo)
	c.Check(info.Onboarded, Equals, false)
	c.Check(info.InProgress, Equals, true)

	session, err := cftor.SessionSetup()
	c.Assert(err, IsNil)

	act = netonboard.OnboardSessionAction{
		Action: "handle",
		Msg:    session,
	}
	b, err = json.Marshal(act)
	c.Assert(err, IsNil)

	req, err = http.NewRequest("POST", "/v2/onboarding/session", bytes.NewReader(b))
	c.Assert(err, IsNil)
	rsp = s.jsonReq(c, req, nil)
	c.Assert(rsp.Status, Equals, 202)
	sessRsp, ok = rsp.Result.(*netonboard.OnboardSessionResponse)
	c.Assert(ok, Equals, true)
	c.Check(sessRsp, DeepEquals, &netonboard.OnboardSessionResponse{
		MsgType:  "ready",
		Exchange: "1",
	})

	// build the ready msg
	act = netonboard.OnboardSessionAction{
		Action:   "reply",
		Exchange: "1",
		D: map[string]interface{}{
			"f.values": []string{"a", "b"},
		},
	}
	b, err = json.Marshal(act)
	c.Assert(err, IsNil)

	req, err = http.NewRequest("POST", "/v2/onboarding/session", bytes.NewReader(b))
	c.Assert(err, IsNil)
	rsp = s.jsonReq(c, req, nil)
	c.Assert(rsp.Status, Equals, 200)
	sessRsp, ok = rsp.Result.(*netonboard.OnboardSessionResponse)
	c.Assert(ok, Equals, true)
	c.Check(sessRsp.MsgType, Equals, "ready")
	// message would be accepted
	d, err := cftor.RcvReady(sessRsp.Msg)
	c.Check(err, IsNil)
	c.Check(d, DeepEquals, map[string]interface{}{
		"f.values": []interface{}{"a", "b"},
	})
}

func (s *onboardSpikeSuite) sessionBegin(c *C) *netonboard.Configurator {
	// generate secrets
	req, err := http.NewRequest("GET", "/v2/onboarding/secrets", nil)
	c.Assert(err, IsNil)
	rsp := s.jsonReq(c, req, nil)
	c.Assert(rsp.Status, Equals, 200)
	secrets := rsp.Result.(*netonboard.OnboardSecrets)

	cftor := &netonboard.Configurator{}
	err = cftor.SetOnboardingSecret(secrets.Secret)
	c.Assert(err, IsNil)

	hello, err := cftor.Hello()
	c.Assert(err, IsNil)

	act := netonboard.OnboardSessionAction{
		Action: "start",
		Msg:    hello,
	}
	b, err := json.Marshal(act)
	c.Assert(err, IsNil)
	req, err = http.NewRequest("POST", "/v2/onboarding/session", bytes.NewReader(b))
	c.Assert(err, IsNil)

	rsp = s.jsonReq(c, req, nil)
	c.Assert(rsp.Status, Equals, 200)
	sessRsp, ok := rsp.Result.(*netonboard.OnboardSessionResponse)
	c.Assert(ok, Equals, true)
	c.Check(sessRsp.MsgType, Equals, "device")
	err = cftor.RcvDevice(sessRsp.Msg)
	c.Check(err, IsNil)

	session, err := cftor.SessionSetup()
	c.Assert(err, IsNil)

	act = netonboard.OnboardSessionAction{
		Action: "handle",
		Msg:    session,
	}
	b, err = json.Marshal(act)
	c.Assert(err, IsNil)

	req, err = http.NewRequest("POST", "/v2/onboarding/session", bytes.NewReader(b))
	c.Assert(err, IsNil)
	rsp = s.jsonReq(c, req, nil)
	c.Assert(rsp.Status, Equals, 202)

	// build the ready msg
	act = netonboard.OnboardSessionAction{
		Action:   "reply",
		Exchange: "1",
	}
	b, err = json.Marshal(act)
	c.Assert(err, IsNil)

	req, err = http.NewRequest("POST", "/v2/onboarding/session", bytes.NewReader(b))
	c.Assert(err, IsNil)
	rsp = s.jsonReq(c, req, nil)
	c.Assert(rsp.Status, Equals, 200)
	sessRsp, ok = rsp.Result.(*netonboard.OnboardSessionResponse)
	c.Assert(ok, Equals, true)
	c.Check(sessRsp.MsgType, Equals, "ready")
	// message would be accepted
	_, err = cftor.RcvReady(sessRsp.Msg)
	c.Check(err, IsNil)

	return cftor
}

func (s *onboardSpikeSuite) TestCfgReply(c *C) {
	s.daemon(c)

	cftor := s.sessionBegin(c)

	cfg, err := cftor.Cfg(map[string]interface{}{
		"f.setup": map[string]interface{}{
			"d": "a",
			"p": "pppp",
		},
	})
	c.Assert(err, IsNil)

	act := netonboard.OnboardSessionAction{
		Action: "handle",
		Msg:    cfg,
	}
	b, err := json.Marshal(act)
	c.Assert(err, IsNil)

	req, err := http.NewRequest("POST", "/v2/onboarding/session", bytes.NewReader(b))
	c.Assert(err, IsNil)
	rsp := s.jsonReq(c, req, nil)
	c.Assert(rsp.Status, Equals, 202)
	sessRsp, ok := rsp.Result.(*netonboard.OnboardSessionResponse)
	c.Assert(ok, Equals, true)
	c.Check(sessRsp, DeepEquals, &netonboard.OnboardSessionResponse{
		MsgType:  "reply",
		Exchange: "2",
		D: map[string]interface{}{
			"f.setup": map[string]interface{}{
				"d": "a",
				"p": "pppp",
			},
		},
	})

	// build the reply msg
	act = netonboard.OnboardSessionAction{
		Action:   "reply",
		Exchange: "2",
		D: map[string]interface{}{
			"f.setup": true,
		},
	}
	b, err = json.Marshal(act)
	c.Assert(err, IsNil)

	req, err = http.NewRequest("POST", "/v2/onboarding/session", bytes.NewReader(b))
	c.Assert(err, IsNil)
	rsp = s.jsonReq(c, req, nil)
	c.Assert(rsp.Status, Equals, 200)
	sessRsp, ok = rsp.Result.(*netonboard.OnboardSessionResponse)
	c.Assert(ok, Equals, true)
	c.Check(sessRsp.MsgType, Equals, "reply")
	// message would be accepted
	d, err := cftor.RcvReply(sessRsp.Msg)
	c.Check(err, IsNil)
	c.Check(d, DeepEquals, map[string]interface{}{
		"f.setup": true,
	})
}
