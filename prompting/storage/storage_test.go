package storage_test

import (
	"reflect"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/prompting/apparmor"
	"github.com/snapcore/snapd/prompting/notifier"
	"github.com/snapcore/snapd/prompting/storage"
)

func Test(t *testing.T) { TestingT(t) }

type storageSuite struct {
	tmpdir string
}

var _ = Suite(&storageSuite{})

func (s *storageSuite) SetUpTest(c *C) {
	s.tmpdir = c.MkDir()
	dirs.SetRootDir(s.tmpdir)
}

func (s *storageSuite) TestSimple(c *C) {
	st := storage.New()

	req := &notifier.Request{
		Label:      "snap.lxd.lxd",
		SubjectUid: 1000,
		Path:       "/home/test/foo/",
		Permission: apparmor.MayReadPermission,
	}

	allowed, err := st.Get(req)
	c.Assert(err, Equals, storage.ErrNoSavedDecision)
	c.Check(allowed, Equals, false)

	allow := true
	extra := map[string]string{}
	extra["allow-subdirectories"] = "yes"
	extra["deny-subdirectories"] = "yes"
	err = st.Set(req, allow, extra)
	c.Assert(err, IsNil)

	paths := st.MapsForUidAndLabelAndPermission(1000, "snap.lxd.lxd", "read").AllowWithSubdirs
	c.Check(paths, HasLen, 1)

	allowed, err = st.Get(req)
	c.Assert(err, IsNil)
	c.Check(allowed, Equals, true)

	// set a more nested path
	req.Path = "/home/test/foo/bar"
	err = st.Set(req, allow, extra)
	c.Assert(err, IsNil)
	// more nested path is not added
	c.Check(paths, HasLen, 1)

	// and more nested path is still allowed
	allowed, err = st.Get(req)
	c.Assert(err, IsNil)
	c.Check(allowed, Equals, true)
}

func (s *storageSuite) TestSubdirOverrides(c *C) {
	st := storage.New()

	req := &notifier.Request{
		Label:      "snap.lxd.lxd",
		SubjectUid: 1000,
		Path:       "/home/test/foo/",
		Permission: apparmor.MayReadPermission,
	}

	allowed, err := st.Get(req)
	c.Assert(err, Equals, storage.ErrNoSavedDecision)
	c.Check(allowed, Equals, false)

	allow := true
	extra := map[string]string{}
	extra["allow-subdirectories"] = "yes"
	extra["deny-subdirectories"] = "yes"
	err = st.Set(req, allow, extra)
	c.Assert(err, IsNil)

	// set a more nested path to not allow
	req.Path = "/home/test/foo/bar/"
	err = st.Set(req, !allow, extra)
	c.Assert(err, IsNil)
	// more nested path was added
	paths := st.MapsForUidAndLabelAndPermission(1000, "snap.lxd.lxd", "read").AllowWithSubdirs
	c.Check(paths, HasLen, 2)

	// and check more nested path is not allowed
	allowed, err = st.Get(req)
	c.Assert(err, IsNil)
	c.Check(allowed, Equals, false)
	// and even more nested path is not allowed
	req.Path = "/home/test/foo/bar/baz"
	allowed, err = st.Get(req)
	c.Assert(err, IsNil)
	c.Check(allowed, Equals, false)
	// but original path is still allowed
	req.Path = "/home/test/foo/"
	allowed, err = st.Get(req)
	c.Assert(err, IsNil)
	c.Check(allowed, Equals, true)

	// set original path to not allow
	err = st.Set(req, !allow, extra)
	c.Assert(err, IsNil)
	// original assignment was overridden
	c.Check(paths, HasLen, 2)
	// TODO: in the future, possibly this should be 1, if we decide to remove
	// subdirectories with the same access from the database when an ancestor
	// directory with the same access is added

	// set a more nested path to allow
	req.Path = "/home/test/foo/bar/"
	err = st.Set(req, allow, extra)
	c.Assert(err, IsNil)
	// more nested path was added
	c.Check(paths, HasLen, 2)

	// and check more nested path is allowed
	allowed, err = st.Get(req)
	c.Assert(err, IsNil)
	c.Check(allowed, Equals, true)
	// and even more nested path is also allowed
	req.Path = "/home/test/foo/bar/baz"
	allowed, err = st.Get(req)
	c.Assert(err, IsNil)
	c.Check(allowed, Equals, true)
	// but original path is still not allowed
	req.Path = "/home/test/foo/"
	allowed, err = st.Get(req)
	c.Assert(err, IsNil)
	c.Check(allowed, Equals, false)
}

func cloneAllowMap(m map[string]bool) map[string]bool {
	newMap := make(map[string]bool, len(m))
	for k, v := range m {
		newMap[k] = v
	}
	return newMap
}

func (s *storageSuite) TestGetMatches(c *C) {
	cases := []struct {
		allow            map[string]bool
		allowWithDir     map[string]bool
		allowWithSubdirs map[string]bool
		path             string
		decision         bool
	}{
		{
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			map[string]bool{},
			"/home/test/foo",
			true,
		},
		{
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			"/home/test/foo",
			true,
		},
		{
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			"/home/test/foo/bar",
			true,
		},
		{
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			"/home/test/foo",
			true,
		},
		{
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			"/home/test/foo/bar",
			true,
		},
		{
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			"/home/test/foo/bar/baz",
			true,
		},
		{
			map[string]bool{"/home/test/foo": false},
			map[string]bool{"/home/test": true},
			map[string]bool{},
			"/home/test/foo",
			false,
		},
		{
			map[string]bool{"/home/test/foo/bar": false},
			map[string]bool{"/home/test": true},
			map[string]bool{},
			"/home/test/foo",
			true,
		},
		{
			map[string]bool{"/home/test": false},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			"/home/test/foo",
			true,
		},
		{
			map[string]bool{"/home/test": false},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			"/home/test/foo/bar",
			true,
		},
		{
			map[string]bool{"/home/test/foo": false},
			map[string]bool{},
			map[string]bool{"/home/test": true},
			"/home/test/foo/bar/baz",
			true,
		},
		{
			map[string]bool{"/home/test/foo": false},
			map[string]bool{},
			map[string]bool{"/home/test": true},
			"/home/test/foo/bar",
			true,
		},
		{
			map[string]bool{"/home/test/foo": false},
			map[string]bool{},
			map[string]bool{"/home/test": true},
			"/home/test/foo",
			false,
		},
		{
			map[string]bool{"/home/test/foo": false},
			map[string]bool{},
			map[string]bool{"/home/test": true},
			"/home/test",
			true,
		},
		{
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{"/home/test": false},
			"/home/test/foo/bar/baz",
			false,
		},
		{
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{"/home/test": false},
			"/home/test/foo/bar",
			true,
		},
		{
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{"/home/test": false},
			"/home/test/foo",
			true,
		},
		{
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{"/home/test": false},
			"/home/test",
			false,
		},
		{
			map[string]bool{"/home/test/foo/bar": false},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{"/home/test": false},
			"/home/test/foo/bar/baz",
			false,
		},
		{
			map[string]bool{"/home/test/foo/bar": false},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{"/home/test": false},
			"/home/test/foo/bar",
			false,
		},
		{
			map[string]bool{"/home/test/foo/bar": true},
			map[string]bool{"/home/test/foo": false},
			map[string]bool{"/home/test": true},
			"/home/test/foo/bar",
			true,
		},
		{
			map[string]bool{"/home/test/foo/bar": false},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{"/home/test": false},
			"/home/test/foo",
			true,
		},
		{
			map[string]bool{"/home/test/foo/bar": true},
			map[string]bool{"/home/test/foo": false},
			map[string]bool{"/home/test": true},
			"/home/test/foo",
			false,
		},
		{
			map[string]bool{"/home/test/foo/bar": false},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{"/home/test": false},
			"/home/test",
			false,
		},
		{
			map[string]bool{"/home/test/foo/bar": true},
			map[string]bool{"/home/test/foo": false},
			map[string]bool{"/home/test": true},
			"/home/test",
			true,
		},
	}

	st := storage.New()

	req := &notifier.Request{
		Label:      "snap.lxd.lxd",
		SubjectUid: 1000,
		Path:       "placeholder",
		Permission: apparmor.MayReadPermission,
	}

	permissionEntries := st.MapsForUidAndLabelAndPermission(req.SubjectUid, req.Label, "read")

	for i, testCase := range cases {
		permissionEntries.Allow = cloneAllowMap(testCase.allow)
		permissionEntries.AllowWithDir = cloneAllowMap(testCase.allowWithDir)
		permissionEntries.AllowWithSubdirs = cloneAllowMap(testCase.allowWithSubdirs)
		req.Path = testCase.path
		allow, err := st.Get(req)
		c.Assert(err, IsNil, Commentf("\nTest case %d:\n%+v\nError: %v", i, testCase, err))
		c.Assert(allow, Equals, testCase.decision, Commentf("\nTest case %d:\n%+v\nGet() returned: %v", i, testCase, allow))
	}
}

func (s *storageSuite) TestGetErrors(c *C) {
	cases := []struct {
		allow            map[string]bool
		allowWithDir     map[string]bool
		allowWithSubdirs map[string]bool
		path             string
		err              error
	}{
		{
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			map[string]bool{},
			"/home/test/foo/bar",
			storage.ErrNoSavedDecision,
		},
		{
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			map[string]bool{},
			"/home/test",
			storage.ErrNoSavedDecision,
		},
		{
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			"/home/test/foo/bar/baz",
			storage.ErrNoSavedDecision,
		},
		{
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			"/home/test",
			storage.ErrNoSavedDecision,
		},
		{
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			"/home/test",
			storage.ErrNoSavedDecision,
		},
		{
			map[string]bool{"/home/test/foo": true},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			"/home/test/foo",
			storage.ErrMultipleDecisions,
		},
		{
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			"/home/test/foo",
			storage.ErrMultipleDecisions,
		},
		{
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{"/home/test/foo": true},
			"/home/test/foo",
			storage.ErrMultipleDecisions,
		},
		{
			map[string]bool{"/home/test/foo": true},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{"/home/test/foo": true},
			"/home/test/foo",
			storage.ErrMultipleDecisions,
		},
	}

	st := storage.New()

	req := &notifier.Request{
		Label:      "snap.lxd.lxd",
		SubjectUid: 1000,
		Path:       "placeholder",
		Permission: apparmor.MayReadPermission,
	}

	permissionEntries := st.MapsForUidAndLabelAndPermission(req.SubjectUid, req.Label, "read")

	for i, testCase := range cases {
		permissionEntries.Allow = cloneAllowMap(testCase.allow)
		permissionEntries.AllowWithDir = cloneAllowMap(testCase.allowWithDir)
		permissionEntries.AllowWithSubdirs = cloneAllowMap(testCase.allowWithSubdirs)
		req.Path = testCase.path
		_, err := st.Get(req)
		c.Assert(err, Equals, testCase.err, Commentf("\nTest case %d:\n%+v\nUnexpected Error: %v", i, testCase, err))
	}
}

func (s *storageSuite) TestSetBehaviorWithMatches(c *C) {
	// if path matches entry already in a different map (XXX means can't return early):
	// new Allow, old Allow -> replace if different
	// new Allow, old AllowWithDir, exact match -> replace if different (forces prompt for entries in directory of path)
	// new Allow, old AllowWithSubdirs, exact match -> same as ^^
	// new Allow, old AllowWithDir, parent match -> insert if different
	// new Allow, old AllowWithSubdirs, ancestor match -> same as ^^
	// new AllowWithDir, old Allow -> replace always XXX
	// new AllowWithDir, old AllowWithDir, exact match -> replace if different
	// new AllowWithDir, old AllowWithSubdirs, exact match -> same as ^^
	// new AllowWithDir, old AllowWithDir, parent match -> insert always XXX
	// new AllowWithDir, old AllowWithSubdirs, ancestor match -> insert if different
	// new AllowWithSubdirs, old Allow -> replace always XXX
	// new AllowWithSubdirs, old AllowWithDir, exact match -> replace always XXX
	// new AllowWithSubdirs, old AllowWithSubdirs, exact match -> replace if different
	// new AllowWithSubdirs, old AllowWithDir, parent match -> insert always XXX
	// new AllowWithSubdirs, old AllowWithSubdirs, ancestor match -> insert if different
	cases := []struct {
		initialAllow            map[string]bool
		initialAllowWithDir     map[string]bool
		initialAllowWithSubdirs map[string]bool
		path                    string
		decision                bool
		extras                  map[string]string
		finalAllow              map[string]bool
		finalAllowWithDir       map[string]bool
		finalAllowWithSubdirs   map[string]bool
	}{
		{ // new Allow, old Allow -> replace if different
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			map[string]bool{},
			"/home/test/foo",
			true,
			map[string]string{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			map[string]bool{},
		},
		{ // new Allow, old Allow -> replace if different
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			map[string]bool{},
			"/home/test/foo",
			false,
			map[string]string{},
			map[string]bool{"/home/test/foo": false},
			map[string]bool{},
			map[string]bool{},
		},
		{ // new Allow, old AllowWithDir, exact match -> replace if different
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			"/home/test/foo",
			true,
			map[string]string{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
		},
		{ // new Allow, old AllowWithDir, exact match -> replace if different
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			"/home/test/foo",
			false,
			map[string]string{},
			map[string]bool{"/home/test/foo": false},
			map[string]bool{},
			map[string]bool{},
		},
		{ // new Allow, old AllowWithDir, exact match -> replace if different
			map[string]bool{},
			map[string]bool{"/home/test/foo": false},
			map[string]bool{},
			"/home/test/foo",
			true,
			map[string]string{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			map[string]bool{},
		},
		{ // new Allow, old AllowWithSubdirs, exact match -> replace if different
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			"/home/test/foo",
			true,
			map[string]string{},
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
		},
		{ // new Allow, old AllowWithSubdirs, exact match -> replace if different
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			"/home/test/foo",
			false,
			map[string]string{},
			map[string]bool{"/home/test/foo": false},
			map[string]bool{},
			map[string]bool{},
		},
		{ // new Allow, old AllowWithSubdirs, exact match -> replace if different
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": false},
			"/home/test/foo",
			true,
			map[string]string{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			map[string]bool{},
		},
		{ // new Allow, old AllowWithDir, parent match -> insert if different
			map[string]bool{},
			map[string]bool{"/home/test": true},
			map[string]bool{},
			"/home/test/foo",
			true,
			map[string]string{},
			map[string]bool{},
			map[string]bool{"/home/test": true},
			map[string]bool{},
		},
		{ // new Allow, old AllowWithDir, parent match -> insert if different
			map[string]bool{},
			map[string]bool{"/home/test": true},
			map[string]bool{},
			"/home/test/foo",
			false,
			map[string]string{},
			map[string]bool{"/home/test/foo": false},
			map[string]bool{"/home/test": true},
			map[string]bool{},
		},
		{ // new Allow, old AllowWithDir, no match -> insert always
			map[string]bool{},
			map[string]bool{"/home/test": true},
			map[string]bool{},
			"/home/test/foo/bar",
			true,
			map[string]string{},
			map[string]bool{"/home/test/foo/bar": true},
			map[string]bool{"/home/test": true},
			map[string]bool{},
		},
		{ // new Allow, old AllowWithSubdirs, ancestor match -> insert if different
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test": true},
			"/home/test/foo/bar",
			true,
			map[string]string{},
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test": true},
		},
		{ // new Allow, old AllowWithSubdirs, ancestor match -> insert if different
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test": true},
			"/home/test/foo/bar",
			false,
			map[string]string{},
			map[string]bool{"/home/test/foo/bar": false},
			map[string]bool{},
			map[string]bool{"/home/test": true},
		},
		{ // new Allow, old AllowWithSubdirs, ancestor match -> insert if different
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test": false},
			"/home/test/foo/bar",
			true,
			map[string]string{},
			map[string]bool{"/home/test/foo/bar": true},
			map[string]bool{},
			map[string]bool{"/home/test": false},
		},
		{ // new Allow, old AllowWithSubdirs, no match -> insert always
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			"/home/test/bar",
			true,
			map[string]string{},
			map[string]bool{"/home/test/bar": true},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
		},
		{ // new Allow, old AllowWithSubdirs, ancestor match -> insert if different
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			"/home/test/bar",
			false,
			map[string]string{},
			map[string]bool{"/home/test/bar": false},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
		},
		{ // new AllowWithDir, old Allow -> replace always
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			map[string]bool{},
			"/home/test/foo/",
			true,
			map[string]string{"allow-directory": "yes"},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
		},
		{ // new AllowWithDir, old Allow -> replace always
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			map[string]bool{},
			"/home/test/foo/",
			false,
			map[string]string{"deny-directory": "yes"},
			map[string]bool{},
			map[string]bool{"/home/test/foo": false},
			map[string]bool{},
		},
		{ // new AllowWithDir, old Allow -> replace always
			map[string]bool{"/home/test/foo": false},
			map[string]bool{},
			map[string]bool{},
			"/home/test/foo/",
			false,
			map[string]string{"deny-directory": "yes"},
			map[string]bool{},
			map[string]bool{"/home/test/foo": false},
			map[string]bool{},
		},
		{ // new AllowWithDir, old AllowWithDir, exact match -> replace if different
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			"/home/test/foo/",
			true,
			map[string]string{"allow-directory": "yes"},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
		},
		{ // new AllowWithDir, old AllowWithDir, exact match -> replace if different
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			"/home/test/foo/",
			false,
			map[string]string{"deny-directory": "yes"},
			map[string]bool{},
			map[string]bool{"/home/test/foo": false},
			map[string]bool{},
		},
		{ // new AllowWithDir, old AllowWithSubdir, exact match -> replace if different
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			"/home/test/foo/",
			true,
			map[string]string{"allow-directory": "yes"},
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
		},
		{ // new AllowWithDir, old AllowWithSubdir, exact match -> replace if different
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			"/home/test/foo/",
			false,
			map[string]string{"deny-directory": "yes"},
			map[string]bool{},
			map[string]bool{"/home/test/foo": false},
			map[string]bool{},
		},
		{ // new AllowWithDir, old AllowWithSubdir, exact match -> replace if different
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": false},
			"/home/test/foo/",
			true,
			map[string]string{"allow-directory": "yes"},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
		},
		{ // new AllowWithDir, old AllowWithSubdir, exact match -> replace if different
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": false},
			"/home/test/foo/",
			false,
			map[string]string{"deny-directory": "yes"},
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": false},
		},
		{ // new AllowWithDir, old AllowWithDir, parent match -> insert always
			map[string]bool{},
			map[string]bool{"/home/test": true},
			map[string]bool{},
			"/home/test/foo/",
			true,
			map[string]string{"allow-directory": "yes"},
			map[string]bool{},
			map[string]bool{"/home/test": true, "/home/test/foo": true},
			map[string]bool{},
		},
		{ // new AllowWithDir, old AllowWithDir, parent match -> insert always
			map[string]bool{},
			map[string]bool{"/home/test": true},
			map[string]bool{},
			"/home/test/foo/",
			false,
			map[string]string{"deny-directory": "yes"},
			map[string]bool{},
			map[string]bool{"/home/test": true, "/home/test/foo": false},
			map[string]bool{},
		},
		{ // new AllowWithDir, old AllowWithSubdir, ancestor match -> insert if different
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test": true},
			"/home/test/foo/bar/",
			true,
			map[string]string{"allow-directory": "yes"},
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test": true},
		},
		{ // new AllowWithDir, old AllowWithSubdir, ancestor match -> insert if different
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test": true},
			"/home/test/foo/bar/",
			false,
			map[string]string{"deny-directory": "yes"},
			map[string]bool{},
			map[string]bool{"/home/test/foo/bar": false},
			map[string]bool{"/home/test": true},
		},
		{ // new AllowWithDir, old AllowWithSubdir, ancestor match -> insert if different
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test": false},
			"/home/test/foo/",
			true,
			map[string]string{"allow-directory": "yes"},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{"/home/test": false},
		},
		{ // new AllowWithSubdirs, old Allow -> replace always
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			map[string]bool{},
			"/home/test/foo/",
			true,
			map[string]string{"allow-subdirectories": "yes"},
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
		},
		{ // new AllowWithSubdirs, old Allow -> replace always
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			map[string]bool{},
			"/home/test/foo/",
			false,
			map[string]string{"deny-subdirectories": "yes"},
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": false},
		},
		{ // new AllowWithSubdirs, old Allow -> replace always
			map[string]bool{"/home/test/foo": false},
			map[string]bool{},
			map[string]bool{},
			"/home/test/foo/",
			false,
			map[string]string{"deny-subdirectories": "yes"},
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": false},
		},
		{ // new AllowWithSubdirs, old AllowWithDir, exact match -> replace always
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			"/home/test/foo/",
			true,
			map[string]string{"allow-subdirectories": "yes"},
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
		},
		{ // new AllowWithSubdirs, old AllowWithDir, exact match -> replace always
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			map[string]bool{},
			"/home/test/foo/",
			false,
			map[string]string{"deny-subdirectories": "yes"},
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": false},
		},
		{ // new AllowWithSubdirs, old AllowWithDir, exact match -> replace always
			map[string]bool{},
			map[string]bool{"/home/test/foo": false},
			map[string]bool{},
			"/home/test/foo/",
			false,
			map[string]string{"deny-subdirectories": "yes"},
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": false},
		},
		{ // new AllowWithSubdirs, old AllowWithDir, exact match -> replace always
			map[string]bool{},
			map[string]bool{"/home/test/foo": false},
			map[string]bool{},
			"/home/test/foo/",
			false,
			map[string]string{"deny-subdirectories": "yes"},
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": false},
		},
		{ // new AllowWithSubdirs, old AllowWithSubdirs, exact match -> replace if different
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			"/home/test/foo/",
			true,
			map[string]string{"allow-subdirectories": "yes"},
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
		},
		{ // new AllowWithSubdirs, old AllowWithSubdirs, exact match -> replace if different
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			"/home/test/foo/",
			false,
			map[string]string{"deny-subdirectories": "yes"},
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": false},
		},
		{ // new AllowWithSubdirs, old AllowWithDir, parent match -> insert always
			map[string]bool{},
			map[string]bool{"/home/test": true},
			map[string]bool{},
			"/home/test/foo/",
			true,
			map[string]string{"allow-subdirectories": "yes"},
			map[string]bool{},
			map[string]bool{"/home/test": true},
			map[string]bool{"/home/test/foo": true},
		},
		{ // new AllowWithSubdirs, old AllowWithDir, parent match -> insert always
			map[string]bool{},
			map[string]bool{"/home/test": true},
			map[string]bool{},
			"/home/test/foo/",
			false,
			map[string]string{"deny-subdirectories": "yes"},
			map[string]bool{},
			map[string]bool{"/home/test": true},
			map[string]bool{"/home/test/foo": false},
		},
		{ // new AllowWithSubdirs, old AllowWithDir, no match -> insert always
			map[string]bool{},
			map[string]bool{"/home/test": true},
			map[string]bool{},
			"/home/test/foo/bar/",
			true,
			map[string]string{"allow-subdirectories": "yes"},
			map[string]bool{},
			map[string]bool{"/home/test": true},
			map[string]bool{"/home/test/foo/bar": true},
		},
		{ // new AllowWithSubdirs, old AllowWithSubdirs, ancestor match -> insert if different
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test": true},
			"/home/test/foo/bar/",
			true,
			map[string]string{"allow-subdirectories": "yes"},
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test": true},
		},
		{ // new AllowWithSubdirs, old AllowWithSubdirs, ancestor match -> insert if different
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test": true},
			"/home/test/foo/bar/",
			false,
			map[string]string{"deny-subdirectories": "yes"},
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test": true, "/home/test/foo/bar": false},
		},
		{ // new AllowWithSubdirs, old AllowWithSubdirs, ancestor match -> insert if different
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test": false},
			"/home/test/foo/",
			false,
			map[string]string{"deny-subdirectories": "yes"},
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test": false},
		},
		{ // new AllowWithSubdirs, old AllowWithSubdirs, no match -> insert always
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true},
			"/home/test/bar/",
			true,
			map[string]string{"allow-subdirectories": "yes"},
			map[string]bool{},
			map[string]bool{},
			map[string]bool{"/home/test/foo": true, "/home/test/bar": true},
		},
	}

	st := storage.New()

	req := &notifier.Request{
		Label:      "snap.lxd.lxd",
		SubjectUid: 1000,
		Path:       "placeholder",
		Permission: apparmor.MayReadPermission,
	}

	permissionEntries := st.MapsForUidAndLabelAndPermission(req.SubjectUid, req.Label, "read")

	for i, testCase := range cases {
		permissionEntries.Allow = cloneAllowMap(testCase.initialAllow)
		permissionEntries.AllowWithDir = cloneAllowMap(testCase.initialAllowWithDir)
		permissionEntries.AllowWithSubdirs = cloneAllowMap(testCase.initialAllowWithSubdirs)
		req.Path = testCase.path
		result := st.Set(req, testCase.decision, testCase.extras)
		c.Assert(reflect.DeepEqual(permissionEntries.Allow, testCase.finalAllow), Equals, true, Commentf("\nTest case %d:\n%+v\nAllow does not match\nActual Allow: %+v\nActual AllowWithDir: %+v\nActualAllowWithSubdirs: %+v\nSet() returned: %v\n", i, testCase, permissionEntries.Allow, permissionEntries.AllowWithDir, permissionEntries.AllowWithSubdirs, result))
		c.Assert(reflect.DeepEqual(permissionEntries.AllowWithDir, testCase.finalAllowWithDir), Equals, true, Commentf("\nTest case %d:\n%+v\nAllowWithDir does not match\nActual Allow: %+v\nActual AllowWithDir: %+v\nActualAllowWithSubdirs: %+v\nSet() returned: %v\n", i, testCase, permissionEntries.Allow, permissionEntries.AllowWithDir, permissionEntries.AllowWithSubdirs, result))
		c.Assert(reflect.DeepEqual(permissionEntries.AllowWithSubdirs, testCase.finalAllowWithSubdirs), Equals, true, Commentf("\nTest case %d:\n%+v\nAllowWithSubdirs does not match\nActual Allow: %+v\nActual AllowWithDir: %+v\nActualAllowWithSubdirs: %+v\nSet() returned: %v\n", i, testCase, permissionEntries.Allow, permissionEntries.AllowWithDir, permissionEntries.AllowWithSubdirs, result))
	}
}

func (s *storageSuite) TestLoadSave(c *C) {
	st := storage.New()

	req := &notifier.Request{
		Label:      "snap.lxd.lxd",
		SubjectUid: 1000,
		Path:       "/home/test/foo",
		Permission: apparmor.MayReadPermission,
	}
	allow := true
	err := st.Set(req, allow, nil)
	c.Assert(err, IsNil)

	// st2 will read DB from the previous storage
	st2 := storage.New()
	allowed, err := st2.Get(req)
	c.Assert(err, IsNil)
	c.Check(allowed, Equals, true)
}