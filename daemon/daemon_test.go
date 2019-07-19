// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2014-2015 Canonical Ltd
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

import (
	"fmt"

	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"gopkg.in/check.v1"

	"github.com/snapcore/snapd/client"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/overlord/auth"
	"github.com/snapcore/snapd/overlord/devicestate/devicestatetest"
	"github.com/snapcore/snapd/overlord/ifacestate"
	"github.com/snapcore/snapd/overlord/patch"
	"github.com/snapcore/snapd/overlord/snapstate"
	"github.com/snapcore/snapd/overlord/standby"
	"github.com/snapcore/snapd/overlord/state"
	"github.com/snapcore/snapd/polkit"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/store"
	"github.com/snapcore/snapd/systemd"
	"github.com/snapcore/snapd/testutil"
)

// Hook up check.v1 into the "go test" runner
func Test(t *testing.T) { check.TestingT(t) }

type daemonSuite struct {
	authorized      bool
	err             error
	lastPolkitFlags polkit.CheckFlags
	notified        []string
	restoreBackends func()
}

var _ = check.Suite(&daemonSuite{})

func (s *daemonSuite) checkAuthorization(pid int32, uid uint32, actionId string, details map[string]string, flags polkit.CheckFlags) (bool, error) {
	s.lastPolkitFlags = flags
	return s.authorized, s.err
}

func (s *daemonSuite) SetUpTest(c *check.C) {
	dirs.SetRootDir(c.MkDir())
	err := os.MkdirAll(filepath.Dir(dirs.SnapStateFile), 0755)
	c.Assert(err, check.IsNil)
	systemdSdNotify = func(notif string) error {
		s.notified = append(s.notified, notif)
		return nil
	}
	s.notified = nil
	polkitCheckAuthorization = s.checkAuthorization
	s.restoreBackends = ifacestate.MockSecurityBackends(nil)
}

func (s *daemonSuite) TearDownTest(c *check.C) {
	systemdSdNotify = systemd.SdNotify
	dirs.SetRootDir("")
	s.authorized = false
	s.err = nil
	logger.SetLogger(logger.NullLogger)
	s.restoreBackends()
}

func (s *daemonSuite) TearDownSuite(c *check.C) {
	polkitCheckAuthorization = polkit.CheckAuthorization
}

// build a new daemon, with only a little of Init(), suitable for the tests
func newTestDaemon(c *check.C) *Daemon {
	d, err := New()
	c.Assert(err, check.IsNil)
	d.addRoutes()

	// don't actually try to talk to the store on snapstate.Ensure
	// needs doing after the call to devicestate.Manager (which
	// happens in daemon.New via overlord.New)
	snapstate.CanAutoRefresh = nil

	return d
}

// a Response suitable for testing
type mockHandler struct {
	cmd        *Command
	lastMethod string
}

func (mck *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mck.lastMethod = r.Method
}

func (s *daemonSuite) TestCommandMethodDispatch(c *check.C) {
	fakeUserAgent := "some-agent-talking-to-snapd/1.0"

	cmd := &Command{d: newTestDaemon(c)}
	mck := &mockHandler{cmd: cmd}
	rf := func(innerCmd *Command, req *http.Request, user *auth.UserState) Response {
		c.Assert(cmd, check.Equals, innerCmd)
		c.Check(store.ClientUserAgent(req.Context()), check.Equals, fakeUserAgent)
		return mck
	}
	cmd.GET = rf
	cmd.PUT = rf
	cmd.POST = rf
	cmd.DELETE = rf

	for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
		req, err := http.NewRequest(method, "", nil)
		req.Header.Add("User-Agent", fakeUserAgent)
		c.Assert(err, check.IsNil)

		rec := httptest.NewRecorder()
		cmd.ServeHTTP(rec, req)
		c.Check(rec.Code, check.Equals, 401, check.Commentf(method))

		rec = httptest.NewRecorder()
		req.RemoteAddr = "pid=100;uid=0;socket=;"

		cmd.ServeHTTP(rec, req)
		c.Check(mck.lastMethod, check.Equals, method)
		c.Check(rec.Code, check.Equals, 200)
	}

	req, err := http.NewRequest("POTATO", "", nil)
	c.Assert(err, check.IsNil)
	req.RemoteAddr = "pid=100;uid=0;socket=;"

	rec := httptest.NewRecorder()
	cmd.ServeHTTP(rec, req)
	c.Check(rec.Code, check.Equals, 405)
}

func (s *daemonSuite) TestCommandRestartingState(c *check.C) {
	d := newTestDaemon(c)

	cmd := &Command{d: d}
	cmd.GET = func(*Command, *http.Request, *auth.UserState) Response {
		return SyncResponse(nil, nil)
	}
	req, err := http.NewRequest("GET", "", nil)
	c.Assert(err, check.IsNil)
	req.RemoteAddr = "pid=100;uid=0;socket=;"

	rec := httptest.NewRecorder()
	cmd.ServeHTTP(rec, req)
	c.Check(rec.Code, check.Equals, 200)
	var rst struct {
		Maintenance *errorResult `json:"maintenance"`
	}
	err = json.Unmarshal(rec.Body.Bytes(), &rst)
	c.Assert(err, check.IsNil)
	c.Check(rst.Maintenance, check.IsNil)

	state.MockRestarting(d.overlord.State(), state.RestartSystem)
	rec = httptest.NewRecorder()
	cmd.ServeHTTP(rec, req)
	c.Check(rec.Code, check.Equals, 200)
	err = json.Unmarshal(rec.Body.Bytes(), &rst)
	c.Assert(err, check.IsNil)
	c.Check(rst.Maintenance, check.DeepEquals, &errorResult{
		Kind:    errorKindSystemRestart,
		Message: "system is restarting",
	})

	state.MockRestarting(d.overlord.State(), state.RestartDaemon)
	rec = httptest.NewRecorder()
	cmd.ServeHTTP(rec, req)
	c.Check(rec.Code, check.Equals, 200)
	err = json.Unmarshal(rec.Body.Bytes(), &rst)
	c.Assert(err, check.IsNil)
	c.Check(rst.Maintenance, check.DeepEquals, &errorResult{
		Kind:    errorKindDaemonRestart,
		Message: "daemon is restarting",
	})
}

func (s *daemonSuite) TestFillsWarnings(c *check.C) {
	d := newTestDaemon(c)

	cmd := &Command{d: d}
	cmd.GET = func(*Command, *http.Request, *auth.UserState) Response {
		return SyncResponse(nil, nil)
	}
	req, err := http.NewRequest("GET", "", nil)
	c.Assert(err, check.IsNil)
	req.RemoteAddr = "pid=100;uid=0;socket=;"

	rec := httptest.NewRecorder()
	cmd.ServeHTTP(rec, req)
	c.Check(rec.Code, check.Equals, 200)
	var rst struct {
		WarningTimestamp *time.Time `json:"warning-timestamp,omitempty"`
		WarningCount     int        `json:"warning-count,omitempty"`
	}
	err = json.Unmarshal(rec.Body.Bytes(), &rst)
	c.Assert(err, check.IsNil)
	c.Check(rst.WarningCount, check.Equals, 0)
	c.Check(rst.WarningTimestamp, check.IsNil)

	st := d.overlord.State()
	st.Lock()
	st.Warnf("hello world")
	st.Unlock()

	rec = httptest.NewRecorder()
	cmd.ServeHTTP(rec, req)
	c.Check(rec.Code, check.Equals, 200)
	err = json.Unmarshal(rec.Body.Bytes(), &rst)
	c.Assert(err, check.IsNil)
	c.Check(rst.WarningCount, check.Equals, 1)
	c.Check(rst.WarningTimestamp, check.NotNil)
}

func (s *daemonSuite) TestGuestAccess(c *check.C) {
	get := &http.Request{Method: "GET"}
	put := &http.Request{Method: "PUT"}
	pst := &http.Request{Method: "POST"}
	del := &http.Request{Method: "DELETE"}

	cmd := &Command{d: newTestDaemon(c)}
	c.Check(cmd.canAccess(get, nil), check.Equals, accessUnauthorized)
	c.Check(cmd.canAccess(put, nil), check.Equals, accessUnauthorized)
	c.Check(cmd.canAccess(pst, nil), check.Equals, accessUnauthorized)
	c.Check(cmd.canAccess(del, nil), check.Equals, accessUnauthorized)

	cmd = &Command{d: newTestDaemon(c), RootOnly: true}
	c.Check(cmd.canAccess(get, nil), check.Equals, accessUnauthorized)
	c.Check(cmd.canAccess(put, nil), check.Equals, accessUnauthorized)
	c.Check(cmd.canAccess(pst, nil), check.Equals, accessUnauthorized)
	c.Check(cmd.canAccess(del, nil), check.Equals, accessUnauthorized)

	cmd = &Command{d: newTestDaemon(c), UserOK: true}
	c.Check(cmd.canAccess(get, nil), check.Equals, accessUnauthorized)
	c.Check(cmd.canAccess(put, nil), check.Equals, accessUnauthorized)
	c.Check(cmd.canAccess(pst, nil), check.Equals, accessUnauthorized)
	c.Check(cmd.canAccess(del, nil), check.Equals, accessUnauthorized)

	cmd = &Command{d: newTestDaemon(c), GuestOK: true}
	c.Check(cmd.canAccess(get, nil), check.Equals, accessOK)
	c.Check(cmd.canAccess(put, nil), check.Equals, accessUnauthorized)
	c.Check(cmd.canAccess(pst, nil), check.Equals, accessUnauthorized)
	c.Check(cmd.canAccess(del, nil), check.Equals, accessUnauthorized)
}

func (s *daemonSuite) TestSnapctlAccessSnapOKWithUser(c *check.C) {
	remoteAddr := "pid=100;uid=1000;socket=" + dirs.SnapSocket + ";"
	get := &http.Request{Method: "GET", RemoteAddr: remoteAddr}
	put := &http.Request{Method: "PUT", RemoteAddr: remoteAddr}
	pst := &http.Request{Method: "POST", RemoteAddr: remoteAddr}
	del := &http.Request{Method: "DELETE", RemoteAddr: remoteAddr}

	cmd := &Command{d: newTestDaemon(c), SnapOK: true}
	c.Check(cmd.canAccess(get, nil), check.Equals, accessOK)
	c.Check(cmd.canAccess(put, nil), check.Equals, accessOK)
	c.Check(cmd.canAccess(pst, nil), check.Equals, accessOK)
	c.Check(cmd.canAccess(del, nil), check.Equals, accessOK)
}

func (s *daemonSuite) TestSnapctlAccessSnapOKWithRoot(c *check.C) {
	remoteAddr := "pid=100;uid=0;socket=" + dirs.SnapSocket + ";"
	get := &http.Request{Method: "GET", RemoteAddr: remoteAddr}
	put := &http.Request{Method: "PUT", RemoteAddr: remoteAddr}
	pst := &http.Request{Method: "POST", RemoteAddr: remoteAddr}
	del := &http.Request{Method: "DELETE", RemoteAddr: remoteAddr}

	cmd := &Command{d: newTestDaemon(c), SnapOK: true}
	c.Check(cmd.canAccess(get, nil), check.Equals, accessOK)
	c.Check(cmd.canAccess(put, nil), check.Equals, accessOK)
	c.Check(cmd.canAccess(pst, nil), check.Equals, accessOK)
	c.Check(cmd.canAccess(del, nil), check.Equals, accessOK)
}

func (s *daemonSuite) TestUserAccess(c *check.C) {
	get := &http.Request{Method: "GET", RemoteAddr: "pid=100;uid=42;socket=;"}
	put := &http.Request{Method: "PUT", RemoteAddr: "pid=100;uid=42;socket=;"}

	cmd := &Command{d: newTestDaemon(c)}
	c.Check(cmd.canAccess(get, nil), check.Equals, accessUnauthorized)
	c.Check(cmd.canAccess(put, nil), check.Equals, accessUnauthorized)

	cmd = &Command{d: newTestDaemon(c), RootOnly: true}
	c.Check(cmd.canAccess(get, nil), check.Equals, accessUnauthorized)
	c.Check(cmd.canAccess(put, nil), check.Equals, accessUnauthorized)

	cmd = &Command{d: newTestDaemon(c), UserOK: true}
	c.Check(cmd.canAccess(get, nil), check.Equals, accessOK)
	c.Check(cmd.canAccess(put, nil), check.Equals, accessUnauthorized)

	cmd = &Command{d: newTestDaemon(c), GuestOK: true}
	c.Check(cmd.canAccess(get, nil), check.Equals, accessOK)
	c.Check(cmd.canAccess(put, nil), check.Equals, accessUnauthorized)

	// Since this request has a RemoteAddr, it must be coming from the snapd
	// socket instead of the snap one. In that case, SnapOK should have no
	// bearing on the default behavior, which is to deny access.
	cmd = &Command{d: newTestDaemon(c), SnapOK: true}
	c.Check(cmd.canAccess(get, nil), check.Equals, accessUnauthorized)
	c.Check(cmd.canAccess(put, nil), check.Equals, accessUnauthorized)
}

func (s *daemonSuite) TestLoggedInUserAccess(c *check.C) {
	user := &auth.UserState{}
	get := &http.Request{Method: "GET", RemoteAddr: "pid=100;uid=42;socket=;"}
	put := &http.Request{Method: "PUT", RemoteAddr: "pid=100;uid=42;socket=;"}

	cmd := &Command{d: newTestDaemon(c)}
	c.Check(cmd.canAccess(get, user), check.Equals, accessOK)
	c.Check(cmd.canAccess(put, user), check.Equals, accessOK)

	cmd = &Command{d: newTestDaemon(c), RootOnly: true}
	c.Check(cmd.canAccess(get, user), check.Equals, accessUnauthorized)
	c.Check(cmd.canAccess(put, user), check.Equals, accessUnauthorized)

	cmd = &Command{d: newTestDaemon(c), UserOK: true}
	c.Check(cmd.canAccess(get, user), check.Equals, accessOK)
	c.Check(cmd.canAccess(put, user), check.Equals, accessOK)

	cmd = &Command{d: newTestDaemon(c), GuestOK: true}
	c.Check(cmd.canAccess(get, user), check.Equals, accessOK)
	c.Check(cmd.canAccess(put, user), check.Equals, accessOK)

	cmd = &Command{d: newTestDaemon(c), SnapOK: true}
	c.Check(cmd.canAccess(get, user), check.Equals, accessOK)
	c.Check(cmd.canAccess(put, user), check.Equals, accessOK)
}

func (s *daemonSuite) TestSuperAccess(c *check.C) {
	get := &http.Request{Method: "GET", RemoteAddr: "pid=100;uid=0;socket=;"}
	put := &http.Request{Method: "PUT", RemoteAddr: "pid=100;uid=0;socket=;"}

	cmd := &Command{d: newTestDaemon(c)}
	c.Check(cmd.canAccess(get, nil), check.Equals, accessOK)
	c.Check(cmd.canAccess(put, nil), check.Equals, accessOK)

	cmd = &Command{d: newTestDaemon(c), RootOnly: true}
	c.Check(cmd.canAccess(get, nil), check.Equals, accessOK)
	c.Check(cmd.canAccess(put, nil), check.Equals, accessOK)

	cmd = &Command{d: newTestDaemon(c), UserOK: true}
	c.Check(cmd.canAccess(get, nil), check.Equals, accessOK)
	c.Check(cmd.canAccess(put, nil), check.Equals, accessOK)

	cmd = &Command{d: newTestDaemon(c), GuestOK: true}
	c.Check(cmd.canAccess(get, nil), check.Equals, accessOK)
	c.Check(cmd.canAccess(put, nil), check.Equals, accessOK)

	cmd = &Command{d: newTestDaemon(c), SnapOK: true}
	c.Check(cmd.canAccess(get, nil), check.Equals, accessOK)
	c.Check(cmd.canAccess(put, nil), check.Equals, accessOK)
}

func (s *daemonSuite) TestPolkitAccess(c *check.C) {
	put := &http.Request{Method: "PUT", RemoteAddr: "pid=100;uid=42;socket=;"}
	cmd := &Command{d: newTestDaemon(c), PolkitOK: "polkit.action"}

	// polkit says user is not authorised
	s.authorized = false
	c.Check(cmd.canAccess(put, nil), check.Equals, accessUnauthorized)

	// polkit grants authorisation
	s.authorized = true
	c.Check(cmd.canAccess(put, nil), check.Equals, accessOK)

	// an error occurs communicating with polkit
	s.err = errors.New("error")
	c.Check(cmd.canAccess(put, nil), check.Equals, accessUnauthorized)

	// if the user dismisses the auth request, forbid access
	s.err = polkit.ErrDismissed
	c.Check(cmd.canAccess(put, nil), check.Equals, accessCancelled)
}

func (s *daemonSuite) TestPolkitAccessForGet(c *check.C) {
	get := &http.Request{Method: "GET", RemoteAddr: "pid=100;uid=42;socket=;"}
	cmd := &Command{d: newTestDaemon(c), PolkitOK: "polkit.action"}

	// polkit can grant authorisation for GET requests
	s.authorized = true
	c.Check(cmd.canAccess(get, nil), check.Equals, accessOK)

	// for UserOK commands, polkit is not consulted
	cmd.UserOK = true
	polkitCheckAuthorization = func(pid int32, uid uint32, actionId string, details map[string]string, flags polkit.CheckFlags) (bool, error) {
		panic("polkit.CheckAuthorization called")
	}
	c.Check(cmd.canAccess(get, nil), check.Equals, accessOK)
}

func (s *daemonSuite) TestPolkitInteractivity(c *check.C) {
	put := &http.Request{Method: "PUT", RemoteAddr: "pid=100;uid=42;socket=;", Header: make(http.Header)}
	cmd := &Command{d: newTestDaemon(c), PolkitOK: "polkit.action"}
	s.authorized = true

	var logbuf bytes.Buffer
	log, err := logger.New(&logbuf, logger.DefaultFlags)
	c.Assert(err, check.IsNil)
	logger.SetLogger(log)

	c.Check(cmd.canAccess(put, nil), check.Equals, accessOK)
	c.Check(s.lastPolkitFlags, check.Equals, polkit.CheckNone)
	c.Check(logbuf.String(), check.Equals, "")

	put.Header.Set(client.AllowInteractionHeader, "true")
	c.Check(cmd.canAccess(put, nil), check.Equals, accessOK)
	c.Check(s.lastPolkitFlags, check.Equals, polkit.CheckAllowInteraction)
	c.Check(logbuf.String(), check.Equals, "")

	// bad values are logged and treated as false
	put.Header.Set(client.AllowInteractionHeader, "garbage")
	c.Check(cmd.canAccess(put, nil), check.Equals, accessOK)
	c.Check(s.lastPolkitFlags, check.Equals, polkit.CheckNone)
	c.Check(logbuf.String(), testutil.Contains, "error parsing X-Allow-Interaction header:")
}

func (s *daemonSuite) TestAddRoutes(c *check.C) {
	d := newTestDaemon(c)

	expected := make([]string, len(api))
	for i, v := range api {
		if v.PathPrefix != "" {
			expected[i] = v.PathPrefix
			continue
		}
		expected[i] = v.Path
	}

	got := make([]string, 0, len(api))
	c.Assert(d.router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		got = append(got, route.GetName())
		return nil
	}), check.IsNil)

	c.Check(got, check.DeepEquals, expected) // this'll stop being true if routes are added that aren't commands (e.g. for the favicon)

	// XXX: still waiting to know how to check d.router.NotFoundHandler has been set to NotFound
	//      the old test relied on undefined behaviour:
	//      c.Check(fmt.Sprintf("%p", d.router.NotFoundHandler), check.Equals, fmt.Sprintf("%p", NotFound))
}

type witnessAcceptListener struct {
	net.Listener

	accept  chan struct{}
	accept1 bool

	idempotClose sync.Once
	closeErr     error
	closed       chan struct{}
}

func (l *witnessAcceptListener) Accept() (net.Conn, error) {
	if !l.accept1 {
		l.accept1 = true
		close(l.accept)
	}
	return l.Listener.Accept()
}

func (l *witnessAcceptListener) Close() error {
	l.idempotClose.Do(func() {
		l.closeErr = l.Listener.Close()
		if l.closed != nil {
			close(l.closed)
		}
	})
	return l.closeErr
}

func (s *daemonSuite) markSeeded(d *Daemon) {
	st := d.overlord.State()
	st.Lock()
	st.Set("seeded", true)
	devicestatetest.SetDevice(st, &auth.DeviceState{
		Brand:  "canonical",
		Model:  "pc",
		Serial: "serialserial",
	})
	st.Unlock()
}

func (s *daemonSuite) TestStartStop(c *check.C) {
	d := newTestDaemon(c)
	// mark as already seeded
	s.markSeeded(d)
	// and pretend we have snaps
	st := d.overlord.State()
	st.Lock()
	snapstate.Set(st, "core", &snapstate.SnapState{
		Active: true,
		Sequence: []*snap.SideInfo{
			{RealName: "core", Revision: snap.R(1), SnapID: "core-snap-id"},
		},
		Current: snap.R(1),
	})
	st.Unlock()

	l1, err := net.Listen("tcp", "127.0.0.1:0")
	c.Assert(err, check.IsNil)
	l2, err := net.Listen("tcp", "127.0.0.1:0")
	c.Assert(err, check.IsNil)

	snapdAccept := make(chan struct{})
	d.snapdListener = &witnessAcceptListener{Listener: l1, accept: snapdAccept}

	snapAccept := make(chan struct{})
	d.snapListener = &witnessAcceptListener{Listener: l2, accept: snapAccept}

	d.Start()

	c.Check(s.notified, check.DeepEquals, []string{"READY=1"})

	snapdDone := make(chan struct{})
	go func() {
		select {
		case <-snapdAccept:
		case <-time.After(2 * time.Second):
			c.Fatal("snapd accept was not called")
		}
		close(snapdDone)
	}()

	snapDone := make(chan struct{})
	go func() {
		select {
		case <-snapAccept:
		case <-time.After(2 * time.Second):
			c.Fatal("snapd accept was not called")
		}
		close(snapDone)
	}()

	<-snapdDone
	<-snapDone

	err = d.Stop(nil)
	c.Check(err, check.IsNil)

	c.Check(s.notified, check.DeepEquals, []string{"READY=1", "STOPPING=1"})
}

func (s *daemonSuite) TestRestartWiring(c *check.C) {
	d := newTestDaemon(c)
	// mark as already seeded
	s.markSeeded(d)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	c.Assert(err, check.IsNil)

	snapdAccept := make(chan struct{})
	d.snapdListener = &witnessAcceptListener{Listener: l, accept: snapdAccept}

	snapAccept := make(chan struct{})
	d.snapListener = &witnessAcceptListener{Listener: l, accept: snapAccept}

	d.Start()
	defer d.Stop(nil)

	snapdDone := make(chan struct{})
	go func() {
		select {
		case <-snapdAccept:
		case <-time.After(2 * time.Second):
			c.Fatal("snapd accept was not called")
		}
		close(snapdDone)
	}()

	snapDone := make(chan struct{})
	go func() {
		select {
		case <-snapAccept:
		case <-time.After(2 * time.Second):
			c.Fatal("snap accept was not called")
		}
		close(snapDone)
	}()

	<-snapdDone
	<-snapDone

	d.overlord.State().RequestRestart(state.RestartDaemon)

	select {
	case <-d.Dying():
	case <-time.After(2 * time.Second):
		c.Fatal("RequestRestart -> overlord -> Kill chain didn't work")
	}
}

func (s *daemonSuite) TestGracefulStop(c *check.C) {
	d := newTestDaemon(c)

	responding := make(chan struct{})
	doRespond := make(chan bool, 1)

	d.router.HandleFunc("/endp", func(w http.ResponseWriter, r *http.Request) {
		close(responding)
		if <-doRespond {
			w.Write([]byte("OKOK"))
		} else {
			w.Write([]byte("Gone"))
		}
		return
	})

	// mark as already seeded
	s.markSeeded(d)
	// and pretend we have snaps
	st := d.overlord.State()
	st.Lock()
	snapstate.Set(st, "core", &snapstate.SnapState{
		Active: true,
		Sequence: []*snap.SideInfo{
			{RealName: "core", Revision: snap.R(1), SnapID: "core-snap-id"},
		},
		Current: snap.R(1),
	})
	st.Unlock()

	snapdL, err := net.Listen("tcp", "127.0.0.1:0")
	c.Assert(err, check.IsNil)

	snapL, err := net.Listen("tcp", "127.0.0.1:0")
	c.Assert(err, check.IsNil)

	snapdAccept := make(chan struct{})
	snapdClosed := make(chan struct{})
	d.snapdListener = &witnessAcceptListener{Listener: snapdL, accept: snapdAccept, closed: snapdClosed}

	snapAccept := make(chan struct{})
	d.snapListener = &witnessAcceptListener{Listener: snapL, accept: snapAccept}

	d.Start()

	snapdAccepting := make(chan struct{})
	go func() {
		select {
		case <-snapdAccept:
		case <-time.After(2 * time.Second):
			c.Fatal("snapd accept was not called")
		}
		close(snapdAccepting)
	}()

	snapAccepting := make(chan struct{})
	go func() {
		select {
		case <-snapAccept:
		case <-time.After(2 * time.Second):
			c.Fatal("snapd accept was not called")
		}
		close(snapAccepting)
	}()

	<-snapdAccepting
	<-snapAccepting

	alright := make(chan struct{})

	go func() {
		res, err := http.Get(fmt.Sprintf("http://%s/endp", snapdL.Addr()))
		c.Assert(err, check.IsNil)
		c.Check(res.StatusCode, check.Equals, 200)
		body, err := ioutil.ReadAll(res.Body)
		res.Body.Close()
		c.Assert(err, check.IsNil)
		c.Check(string(body), check.Equals, "OKOK")
		close(alright)
	}()
	go func() {
		<-snapdClosed
		time.Sleep(200 * time.Millisecond)
		doRespond <- true
	}()

	<-responding
	err = d.Stop(nil)
	doRespond <- false
	c.Check(err, check.IsNil)

	select {
	case <-alright:
	case <-time.After(2 * time.Second):
		c.Fatal("never got proper response")
	}
}

func (s *daemonSuite) TestRestartSystemWiring(c *check.C) {
	d := newTestDaemon(c)
	// mark as already seeded
	s.markSeeded(d)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	c.Assert(err, check.IsNil)

	snapdAccept := make(chan struct{})
	d.snapdListener = &witnessAcceptListener{Listener: l, accept: snapdAccept}

	snapAccept := make(chan struct{})
	d.snapListener = &witnessAcceptListener{Listener: l, accept: snapAccept}

	d.Start()
	defer d.Stop(nil)

	st := d.overlord.State()

	snapdDone := make(chan struct{})
	go func() {
		select {
		case <-snapdAccept:
		case <-time.After(2 * time.Second):
			c.Fatal("snapd accept was not called")
		}
		close(snapdDone)
	}()

	snapDone := make(chan struct{})
	go func() {
		select {
		case <-snapAccept:
		case <-time.After(2 * time.Second):
			c.Fatal("snap accept was not called")
		}
		close(snapDone)
	}()

	<-snapdDone
	<-snapDone

	oldRebootNoticeWait := rebootNoticeWait
	oldRebootWaitTimeout := rebootWaitTimeout
	defer func() {
		reboot = rebootImpl
		rebootNoticeWait = oldRebootNoticeWait
		rebootWaitTimeout = oldRebootWaitTimeout
	}()
	rebootWaitTimeout = 100 * time.Millisecond
	rebootNoticeWait = 150 * time.Millisecond

	var delays []time.Duration
	reboot = func(d time.Duration) error {
		delays = append(delays, d)
		return nil
	}

	st.Lock()
	st.RequestRestart(state.RestartSystem)
	st.Unlock()

	defer func() {
		d.mu.Lock()
		d.restartSystem = false
		d.mu.Unlock()
	}()

	select {
	case <-d.Dying():
	case <-time.After(2 * time.Second):
		c.Fatal("RequestRestart -> overlord -> Kill chain didn't work")
	}

	d.mu.Lock()
	rs := d.restartSystem
	d.mu.Unlock()

	c.Check(rs, check.Equals, true)

	c.Check(delays, check.HasLen, 1)
	c.Check(delays[0], check.DeepEquals, rebootWaitTimeout)

	now := time.Now()

	err = d.Stop(nil)

	c.Check(err, check.ErrorMatches, "expected reboot did not happen")

	c.Check(delays, check.HasLen, 2)
	c.Check(delays[1], check.DeepEquals, 1*time.Minute)

	// we are not stopping, we wait for the reboot instead
	c.Check(s.notified, check.DeepEquals, []string{"READY=1"})

	st.Lock()
	defer st.Unlock()
	var rebootAt time.Time
	err = st.Get("daemon-system-restart-at", &rebootAt)
	c.Assert(err, check.IsNil)
	approxAt := now.Add(time.Minute)
	c.Check(rebootAt.After(approxAt) || rebootAt.Equal(approxAt), check.Equals, true)
}

func (s *daemonSuite) TestRebootHelper(c *check.C) {
	cmd := testutil.MockCommand(c, "shutdown", "")
	defer cmd.Restore()

	tests := []struct {
		delay    time.Duration
		delayArg string
	}{
		{-1, "+0"},
		{0, "+0"},
		{time.Minute, "+1"},
		{10 * time.Minute, "+10"},
		{30 * time.Second, "+0"},
	}

	for _, t := range tests {
		err := reboot(t.delay)
		c.Assert(err, check.IsNil)
		c.Check(cmd.Calls(), check.DeepEquals, [][]string{
			{"shutdown", "-r", t.delayArg, "reboot scheduled to update the system"},
		})

		cmd.ForgetCalls()
	}
}

func makeDaemonListeners(c *check.C, d *Daemon) {
	snapdL, err := net.Listen("tcp", "127.0.0.1:0")
	c.Assert(err, check.IsNil)

	snapL, err := net.Listen("tcp", "127.0.0.1:0")
	c.Assert(err, check.IsNil)

	snapdAccept := make(chan struct{})
	snapdClosed := make(chan struct{})
	d.snapdListener = &witnessAcceptListener{Listener: snapdL, accept: snapdAccept, closed: snapdClosed}

	snapAccept := make(chan struct{})
	d.snapListener = &witnessAcceptListener{Listener: snapL, accept: snapAccept}
}

// This test tests that when the snapd calls a restart of the system
// a sigterm (from e.g. systemd) is handled when it arrives before
// stop is fully done.
func (s *daemonSuite) TestRestartShutdownWithSigtermInBetween(c *check.C) {
	oldRebootNoticeWait := rebootNoticeWait
	defer func() {
		rebootNoticeWait = oldRebootNoticeWait
	}()
	rebootNoticeWait = 150 * time.Millisecond

	cmd := testutil.MockCommand(c, "shutdown", "")
	defer cmd.Restore()

	d := newTestDaemon(c)
	makeDaemonListeners(c, d)
	s.markSeeded(d)

	d.Start()
	st := d.overlord.State()

	st.Lock()
	st.RequestRestart(state.RestartSystem)
	st.Unlock()

	ch := make(chan os.Signal, 2)
	ch <- syscall.SIGTERM
	// stop will check if we got a sigterm in between (which we did)
	err := d.Stop(ch)
	c.Assert(err, check.IsNil)
}

// This test tests that when there is a shutdown we close the sigterm
// handler so that systemd can kill snapd.
func (s *daemonSuite) TestRestartShutdown(c *check.C) {
	oldRebootNoticeWait := rebootNoticeWait
	oldRebootWaitTimeout := rebootWaitTimeout
	defer func() {
		rebootNoticeWait = oldRebootNoticeWait
		rebootWaitTimeout = oldRebootWaitTimeout
	}()
	rebootWaitTimeout = 100 * time.Millisecond
	rebootNoticeWait = 150 * time.Millisecond

	cmd := testutil.MockCommand(c, "shutdown", "")
	defer cmd.Restore()

	d := newTestDaemon(c)
	makeDaemonListeners(c, d)
	s.markSeeded(d)

	d.Start()
	st := d.overlord.State()

	st.Lock()
	st.RequestRestart(state.RestartSystem)
	st.Unlock()

	sigCh := make(chan os.Signal, 2)
	// stop (this will timeout but thats not relevant for this test)
	d.Stop(sigCh)

	// ensure that the sigCh got closed as part of the stop
	_, chOpen := <-sigCh
	c.Assert(chOpen, check.Equals, false)
}

func (s *daemonSuite) TestRestartExpectedRebootDidNotHappen(c *check.C) {
	curBootID, err := osutil.BootID()
	c.Assert(err, check.IsNil)

	fakeState := []byte(fmt.Sprintf(`{"data":{"patch-level":%d,"patch-sublevel":%d,"some":"data","refresh-privacy-key":"0123456789ABCDEF","system-restart-from-boot-id":%q,"daemon-system-restart-at":"%s"},"changes":null,"tasks":null,"last-change-id":0,"last-task-id":0,"last-lane-id":0}`, patch.Level, patch.Sublevel, curBootID, time.Now().UTC().Format(time.RFC3339)))
	err = ioutil.WriteFile(dirs.SnapStateFile, fakeState, 0600)
	c.Assert(err, check.IsNil)

	oldRebootNoticeWait := rebootNoticeWait
	oldRebootRetryWaitTimeout := rebootRetryWaitTimeout
	defer func() {
		rebootNoticeWait = oldRebootNoticeWait
		rebootRetryWaitTimeout = oldRebootRetryWaitTimeout
	}()
	rebootRetryWaitTimeout = 100 * time.Millisecond
	rebootNoticeWait = 150 * time.Millisecond

	cmd := testutil.MockCommand(c, "shutdown", "")
	defer cmd.Restore()

	d := newTestDaemon(c)
	c.Check(d.overlord, check.IsNil)
	c.Check(d.expectedRebootDidNotHappen, check.Equals, true)

	var n int
	d.state.Lock()
	err = d.state.Get("daemon-system-restart-tentative", &n)
	d.state.Unlock()
	c.Check(err, check.IsNil)
	c.Check(n, check.Equals, 1)

	d.Start()

	c.Check(s.notified, check.DeepEquals, []string{"READY=1"})

	select {
	case <-d.Dying():
	case <-time.After(2 * time.Second):
		c.Fatal("expected reboot not happening should proceed to try to shutdown again")
	}

	sigCh := make(chan os.Signal, 2)
	// stop (this will timeout but thats not relevant for this test)
	d.Stop(sigCh)

	// an immediate shutdown was scheduled again
	c.Check(cmd.Calls(), check.DeepEquals, [][]string{
		{"shutdown", "-r", "+0", "reboot scheduled to update the system"},
	})
}

func (s *daemonSuite) TestRestartExpectedRebootOK(c *check.C) {
	fakeState := []byte(fmt.Sprintf(`{"data":{"patch-level":%d,"patch-sublevel":%d,"some":"data","refresh-privacy-key":"0123456789ABCDEF","system-restart-from-boot-id":%q,"daemon-system-restart-at":"%s"},"changes":null,"tasks":null,"last-change-id":0,"last-task-id":0,"last-lane-id":0}`, patch.Level, patch.Sublevel, "boot-id-0", time.Now().UTC().Format(time.RFC3339)))
	err := ioutil.WriteFile(dirs.SnapStateFile, fakeState, 0600)
	c.Assert(err, check.IsNil)

	cmd := testutil.MockCommand(c, "shutdown", "")
	defer cmd.Restore()

	d := newTestDaemon(c)
	c.Assert(d.overlord, check.NotNil)

	st := d.overlord.State()
	st.Lock()
	defer st.Unlock()
	var v interface{}
	// these were cleared
	c.Check(st.Get("daemon-system-restart-at", &v), check.Equals, state.ErrNoState)
	c.Check(st.Get("system-restart-from-boot-id", &v), check.Equals, state.ErrNoState)
}

func (s *daemonSuite) TestRestartExpectedRebootGiveUp(c *check.C) {
	// we give up trying to restart the system after 3 retry tentatives
	curBootID, err := osutil.BootID()
	c.Assert(err, check.IsNil)

	fakeState := []byte(fmt.Sprintf(`{"data":{"patch-level":%d,"patch-sublevel":%d,"some":"data","refresh-privacy-key":"0123456789ABCDEF","system-restart-from-boot-id":%q,"daemon-system-restart-at":"%s","daemon-system-restart-tentative":3},"changes":null,"tasks":null,"last-change-id":0,"last-task-id":0,"last-lane-id":0}`, patch.Level, patch.Sublevel, curBootID, time.Now().UTC().Format(time.RFC3339)))
	err = ioutil.WriteFile(dirs.SnapStateFile, fakeState, 0600)
	c.Assert(err, check.IsNil)

	cmd := testutil.MockCommand(c, "shutdown", "")
	defer cmd.Restore()

	d := newTestDaemon(c)
	c.Assert(d.overlord, check.NotNil)

	st := d.overlord.State()
	st.Lock()
	defer st.Unlock()
	var v interface{}
	// these were cleared
	c.Check(st.Get("daemon-system-restart-at", &v), check.Equals, state.ErrNoState)
	c.Check(st.Get("system-restart-from-boot-id", &v), check.Equals, state.ErrNoState)
	c.Check(st.Get("daemon-system-restart-tentative", &v), check.Equals, state.ErrNoState)
}

func (s *daemonSuite) TestRestartIntoSocketModeNoNewChanges(c *check.C) {
	restore := standby.MockStandbyWait(5 * time.Millisecond)
	defer restore()

	d := newTestDaemon(c)
	makeDaemonListeners(c, d)

	// mark as already seeded, we also have no snaps so this will
	// go into socket activation mode
	s.markSeeded(d)

	d.Start()
	// pretend some ensure happened
	for i := 0; i < 5; i++ {
		d.overlord.StateEngine().Ensure()
		time.Sleep(5 * time.Millisecond)
	}

	select {
	case <-d.Dying():
		// exit the loop
	case <-time.After(15 * time.Second):
		c.Errorf("daemon did not stop after 15s")
	}
	err := d.Stop(nil)
	c.Check(err, check.Equals, ErrRestartSocket)
	c.Check(d.restartSocket, check.Equals, true)
}

func (s *daemonSuite) TestRestartIntoSocketModePendingChanges(c *check.C) {
	restore := standby.MockStandbyWait(5 * time.Millisecond)
	defer restore()

	d := newTestDaemon(c)
	makeDaemonListeners(c, d)

	// mark as already seeded, we also have no snaps so this will
	// go into socket activation mode
	s.markSeeded(d)
	st := d.overlord.State()

	d.Start()
	// pretend some ensure happened
	for i := 0; i < 5; i++ {
		d.overlord.StateEngine().Ensure()
		time.Sleep(5 * time.Millisecond)
	}

	select {
	case <-d.Dying():
		// Pretend we got change while shutting down, this can
		// happen when e.g. the user requested a `snap install
		// foo` at the same time as the code in the overlord
		// checked that it can go into socket activated
		// mode. I.e. the daemon was processing the request
		// but no change was generated at the time yet.
		st.Lock()
		chg := st.NewChange("fake-install", "fake install some snap")
		chg.AddTask(st.NewTask("fake-install-task", "fake install task"))
		chgStatus := chg.Status()
		st.Unlock()
		// ensure our change is valid and ready
		c.Check(chgStatus, check.Equals, state.DoStatus)
	case <-time.After(5 * time.Second):
		c.Errorf("daemon did not stop after 5s")
	}
	// when the daemon got a pending change it just restarts
	err := d.Stop(nil)
	c.Check(err, check.IsNil)
	c.Check(d.restartSocket, check.Equals, false)
}

func (s *daemonSuite) TestConnTrackerCanShutdown(c *check.C) {
	ct := &connTracker{conns: make(map[net.Conn]struct{})}
	c.Check(ct.CanStandby(), check.Equals, true)

	con := &net.IPConn{}
	ct.trackConn(con, http.StateActive)
	c.Check(ct.CanStandby(), check.Equals, false)

	ct.trackConn(con, http.StateIdle)
	c.Check(ct.CanStandby(), check.Equals, true)
}

func doTestReq(c *check.C, cmd *Command, mth string) *httptest.ResponseRecorder {
	req, err := http.NewRequest(mth, "", nil)
	c.Assert(err, check.IsNil)
	req.RemoteAddr = "pid=100;uid=0;socket=;"
	rec := httptest.NewRecorder()
	cmd.ServeHTTP(rec, req)
	return rec
}

func (s *daemonSuite) TestDegradedModeReply(c *check.C) {
	d := newTestDaemon(c)
	cmd := &Command{d: d}
	cmd.GET = func(*Command, *http.Request, *auth.UserState) Response {
		return SyncResponse(nil, nil)
	}
	cmd.POST = func(*Command, *http.Request, *auth.UserState) Response {
		return SyncResponse(nil, nil)
	}

	// pretend we are in degraded mode
	d.SetDegradedMode(fmt.Errorf("foo error"))

	// GET is ok even in degraded mode
	rec := doTestReq(c, cmd, "GET")
	c.Check(rec.Code, check.Equals, 200)
	// POST is not allowed
	rec = doTestReq(c, cmd, "POST")
	c.Check(rec.Code, check.Equals, 500)
	// verify we get the error
	var v struct{ Result errorResult }
	c.Assert(json.NewDecoder(rec.Body).Decode(&v), check.IsNil)
	c.Check(v.Result.Message, check.Equals, "foo error")

	// clean degraded mode
	d.SetDegradedMode(nil)
	rec = doTestReq(c, cmd, "POST")
	c.Check(rec.Code, check.Equals, 200)
}
