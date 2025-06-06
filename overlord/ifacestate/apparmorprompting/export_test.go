// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

package apparmorprompting

import (
	"github.com/snapcore/snapd/interfaces/prompting/requestprompts"
	"github.com/snapcore/snapd/interfaces/prompting/requestrules"
	"github.com/snapcore/snapd/sandbox/apparmor/notify"
	"github.com/snapcore/snapd/sandbox/apparmor/notify/listener"
	"github.com/snapcore/snapd/testutil"
)

func MockListenerRegister(f func() (*listener.Listener, error)) (restore func()) {
	return testutil.Mock(&listenerRegister, f)
}

func MockListenerRun(f func(l *listener.Listener) error) (restore func()) {
	return testutil.Mock(&listenerRun, f)
}

func MockListenerReady(f func(l *listener.Listener) <-chan struct{}) (restore func()) {
	return testutil.Mock(&listenerReady, f)
}

func MockListenerReqs(f func(l *listener.Listener) <-chan *listener.Request) (restore func()) {
	return testutil.Mock(&listenerReqs, f)
}

func MockListenerClose(f func(l *listener.Listener) error) (restore func()) {
	return testutil.Mock(&listenerClose, f)
}

type RequestResponse struct {
	Request           *listener.Request
	AllowedPermission notify.AppArmorPermission
}

func MockListener() (readyChan chan struct{}, reqChan chan *listener.Request, replyChan chan RequestResponse, restore func()) {
	// The readyChan should be closed once all pending previously-sent requests
	// have been re-sent.
	readyChan = make(chan struct{})
	// Since the manager run loop is in a tracked goroutine, shouldn't block.
	reqChan = make(chan *listener.Request)
	// Replies would be sent synchronously to an async listener, but it's
	// mocked to be synchronous, so we need a non-zero buffer here.
	replyChan = make(chan RequestResponse, 5)

	closeChan := make(chan struct{})

	restoreRegister := MockListenerRegister(func() (*listener.Listener, error) {
		return &listener.Listener{}, nil
	})
	restoreRun := MockListenerRun(func(l *listener.Listener) error {
		<-closeChan
		// In production, listener.Run() does not return on error, and when
		// the listener is closed, it returns nil. So it should always return
		// nil in practice.
		return nil
	})
	restoreReady := MockListenerReady(func(l *listener.Listener) <-chan struct{} {
		return readyChan
	})
	restoreReqs := MockListenerReqs(func(l *listener.Listener) <-chan *listener.Request {
		return reqChan
	})
	restoreClose := MockListenerClose(func(l *listener.Listener) error {
		select {
		case <-closeChan:
			return listener.ErrAlreadyClosed
		default:
			close(reqChan)
			close(replyChan)
			close(closeChan)
		}
		select {
		case <-readyChan:
			// already closed
		default:
			close(readyChan)
		}
		return nil
	})
	restoreReply := MockRequestReply(func(req *listener.Request, allowedPermission notify.AppArmorPermission) error {
		reqResp := RequestResponse{
			Request:           req,
			AllowedPermission: allowedPermission,
		}
		replyChan <- reqResp
		return nil
	})
	restore = func() {
		restoreReply()
		restoreClose()
		restoreReqs()
		restoreReady()
		restoreRun()
		restoreRegister()
	}
	return readyChan, reqChan, replyChan, restore
}

func MockRequestReply(f func(req *listener.Request, allowedPermission notify.AppArmorPermission) error) (restore func()) {
	restoreRequestReply := testutil.Backup(&requestReply)
	requestReply = f
	restoreRequestpromptsSendReply := requestprompts.MockSendReply(f)
	return func() {
		restoreRequestpromptsSendReply()
		restoreRequestReply()
	}
}

// Export the manager-level ready channel so it can be used in tests.
func (m *InterfacesRequestsManager) Ready() <-chan struct{} {
	return m.ready
}

func MockPromptsHandleReadying(f func(pdb *requestprompts.PromptDB) error) (restore func()) {
	return testutil.Mock(&promptsHandleReadying, f)
}

func MockPromptingInterfaceFromTagsets(f func(tagsets notify.TagsetMap) (string, error)) (restore func()) {
	return testutil.Mock(&promptingInterfaceFromTagsets, f)
}

func (m *InterfacesRequestsManager) PromptDB() *requestprompts.PromptDB {
	return m.prompts
}

func (m *InterfacesRequestsManager) RuleDB() *requestrules.RuleDB {
	return m.rules
}
