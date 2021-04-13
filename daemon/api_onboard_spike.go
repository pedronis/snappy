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

package daemon

/* *** THIS IS SPIKE CODE ***

A real implementation would live and be integrated with devicestate.

*/

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	jose "gopkg.in/square/go-jose.v2"

	"github.com/snapcore/snapd/netonboard"
	"github.com/snapcore/snapd/overlord/auth"
	"github.com/snapcore/snapd/overlord/snapstate"
	"github.com/snapcore/snapd/overlord/state"
)

var (
	onboardingInfoCmd = &Command{
		Path: "/v2/onboarding",
		GET:  getOnboardInfo,
	}

	onboardingSecretsCmd = &Command{
		Path: "/v2/onboarding/secrets",
		GET:  getOnboardSecrets,
		// POST: setOnboardSecrets,
		RootOnly: true,
	}

	onboardingSessionCmd = &Command{
		Path:     "/v2/onboarding/session",
		POST:     postOnboardSession,
		RootOnly: true,
	}
)

type onboardState struct {
	Onboarded bool `json:"onboarded"`

	Secret    []byte           `json:"secret,omitempty"`
	DeviceKey *jose.JSONWebKey `json:"device-key,omitempty"`

	InProgress bool `json:"in-progress"`
}

func getOnboardState(st *state.State) (*onboardState, error) {
	var onbst onboardState
	err := st.Get("onboarding", &onbst)
	if err != nil && err != state.ErrNoState {
		return nil, err
	}
	return &onbst, nil
}

func setOnboardState(st *state.State, onbst *onboardState) {
	st.Set("onboarding", onbst)
}

func getOnboardInfo(c *Command, r *http.Request, user *auth.UserState) Response {
	st := c.d.overlord.State()
	st.Lock()
	defer st.Unlock()

	onbst, err := getOnboardState(st)
	if err != nil {
		return InternalError("cannot get onboarding state %v", err)
	}

	return SyncResponse(&netonboard.OnboardInfo{
		Onboarded:  onbst.Onboarded,
		InProgress: onbst.InProgress,
	}, nil)
}

func getOnboardSecrets(c *Command, r *http.Request, user *auth.UserState) Response {
	st := c.d.overlord.State()
	st.Lock()
	defer st.Unlock()

	onbst, err := getOnboardState(st)
	if err != nil {
		return InternalError("cannot get onboarding state %v", err)
	}

	// XXX we might not want generating all secrets as default
	// behavior ultimately
	save := false
	if onbst.Secret == nil {
		save = true
		s, err := netonboard.GenSecret()
		if err != nil {
			return InternalError("%v", err)
		}
		onbst.Secret = s
	}
	if onbst.DeviceKey == nil {
		save = true
		dk, err := netonboard.GenDeviceKey()
		if err != nil {
			return InternalError("%v", err)
		}
		onbst.DeviceKey = &jose.JSONWebKey{
			Key: dk,
		}
	}
	if save {
		setOnboardState(st, onbst)
	}

	pk := onbst.DeviceKey.Public()
	return SyncResponse(&netonboard.OnboardSecrets{
		Secret:    onbst.Secret,
		DeviceKey: &pk,
	}, nil)
}

func postOnboardSession(c *Command, r *http.Request, user *auth.UserState) Response {
	var act netonboard.OnboardSessionAction

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&act); err != nil {
		return BadRequest("cannot decode request into session action: %v", err)
	}

	st := c.d.overlord.State()
	st.Lock()
	defer st.Unlock()

	onbst, err := getOnboardState(st)
	if err != nil {
		return InternalError("cannot get onboarding state %v", err)
	}

	if onbst.Onboarded {
		// XXX dedicated error
		return BadRequest("already onboarded")
	}

	sess := getSession(st)
	switch act.Action {
	case "start":
		if onbst.InProgress {
			// XXX dedicated conflict error?
			return Conflict("already onboarding")
		}
		_, err := snapstate.DevicePastSeeding(st, nil)
		if err != nil {
			return errToResponse(err, nil, InternalError, "cannot determine if seeded")
		}
		sess, err := setupSession(st, onbst)
		if err != nil {
			return InternalError("%v", err)
		}
		if err := sess.proto.RcvHello(act.Msg); err != nil {
			return handleOnboardError(err)
		}
		device, err := sess.proto.Device()
		if err != nil {
			return handleOnboardError(err)
		}
		onbst.InProgress = true
		setOnboardState(st, onbst)
		return SyncResponse(&netonboard.OnboardSessionResponse{
			MsgType: "device",
			Msg:     device,
		}, nil)
	case "handle":
		if sess == nil {
			return BadRequest("no current onboarding session")
		}
		rsp, noError := sess.handle(act.Msg)
		if !noError {
			// if there's an error handling a message from
			// the configurator we clear the session
			// automatically, it's also possible to use
			// action fatal to do that
			clearSession(st, onbst)
		}
		return rsp
	case "reply":
		if sess == nil {
			return BadRequest("no current onboarding session")
		}
		return sess.reply(act.Exchange, act.D)
	case "fatal":
		if sess == nil {
			return BadRequest("no current onboarding session")
		}
		oe := &netonboard.Error{
			Code: act.FatalCode,
			Msg:  act.FatalMsg,
		}
		resp := buildFatalResponse(oe, 200)
		clearSession(st, onbst)
		return resp
	default:
		return BadRequest("unknown session action %q", act.Action)
	}
}

type onboardSession struct {
	proto *netonboard.Device

	exchange    int
	replyingFor int
}

// XXX have a session timeout
// XXX have possibly a session rate limit?

func (s *onboardSession) handle(msg []byte) (rsp Response, noError bool) {
	if s.replyingFor != 0 {
		return BadRequest("still replying to previous message"), false
	}
	var in map[string]interface{}
	var answerType string
	if s.exchange == 0 {
		err := s.proto.RcvSessionSetup(msg)
		if err != nil {
			return handleOnboardError(err), false
		}
		answerType = "ready"
		s.exchange = 1
	} else {
		var err error
		in, err = s.proto.RcvCfg(msg)
		if err != nil {
			return handleOnboardError(err), false
		}
		answerType = "reply"
		s.exchange += 1
	}
	// XXX filter out from in directives that snapd should understand
	// something like an "onboard": params directive would switch to
	// the actual onboarding, tryign network config...
	// XXX here we can start a Change mapped to the exchange if needed
	s.replyingFor = s.exchange
	return onboardExchangeResponse(answerType, s.exchange, in), true
}

func onboardExchangeResponse(msgType string, exchange int, d map[string]interface{}) Response {
	return &resp{
		Type:   ResponseTypeSync,
		Status: 202,
		Result: &netonboard.OnboardSessionResponse{
			MsgType:  msgType,
			Exchange: strconv.Itoa(exchange),
			D:        d,
		},
	}
}

func (s *onboardSession) reply(exchange string, d map[string]interface{}) Response {
	exchg, _ := strconv.Atoi(exchange)
	if exchg == 0 || exchg != s.replyingFor {
		return BadRequest("mismatched exchange")
	}
	// XXX if Change is not done return an Exchange-set response again
	// XXX combine d with our own results
	var answerType string
	var buildMsg func(map[string]interface{}) ([]byte, error)
	var msg []byte
	if s.exchange == 1 {
		answerType = "ready"
		buildMsg = s.proto.Ready
	} else {
		answerType = "reply"
		buildMsg = s.proto.Reply
	}
	msg, err := buildMsg(d)
	if err != nil {
		return handleOnboardError(err)
	}
	s.replyingFor = 0
	return SyncResponse(&netonboard.OnboardSessionResponse{
		MsgType: answerType,
		Msg:     msg,
	}, nil)
}

func buildFatalResponse(oe *netonboard.Error, status int) Response {
	f, err := netonboard.Fatal(oe)
	if err != nil {
		return InternalError(err.Error())
	}
	res := &errorResult{
		Message: oe.Msg,
		Kind:    netonboard.ErrorKindFatal,
		Value: netonboard.ErrorValue{
			Fatal: f,
		},
	}
	return &resp{
		Type:   ResponseTypeError,
		Result: res,
		Status: status,
	}
}

func handleOnboardError(e error) Response {
	switch oe := e.(type) {
	case *netonboard.Error:
		return buildFatalResponse(oe, 400)
	case netonboard.FatalError:
		res := &errorResult{
			Message: oe.Err.Msg,
			Kind:    netonboard.ErrorKindFatalReceived,
			Value: netonboard.ErrorValue{
				Code: oe.Err.Code,
			},
		}
		return &resp{
			Type:   ResponseTypeError,
			Result: res,
			Status: 400,
		}
	default:
		return InternalError(e.Error())
	}
}

type onboardSessionKey struct{}

func setupSession(st *state.State, onbst *onboardState) (*onboardSession, error) {
	// XXX this uses the state cache as a shortcut
	// A complete implementation need to survive snapd restarts
	if onbst.Secret == nil || onbst.DeviceKey == nil {
		return nil, fmt.Errorf("cannot start onboarding with secrets unset")
	}
	dev := &netonboard.Device{}
	if err := dev.SetOnboardingSecret(onbst.Secret); err != nil {
		return nil, err
	}
	dk := onbst.DeviceKey.Key.(*ecdsa.PrivateKey)
	if err := dev.SetOnboardingDeviceKey(dk); err != nil {
		return nil, err
	}
	sess := &onboardSession{
		proto: dev,
	}
	st.Cache(onboardSessionKey{}, sess)
	return sess, nil
}

func clearSession(st *state.State, onbst *onboardState) {
	onbst.InProgress = false
	setOnboardState(st, onbst)
	st.Cache(onboardSessionKey{}, nil)
}

func getSession(st *state.State) *onboardSession {
	v := st.Cached(onboardSessionKey{})
	if v == nil {
		return nil
	}
	return v.(*onboardSession)
}
