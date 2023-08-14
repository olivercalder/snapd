package common_test

import (
	"encoding/base32"
	"encoding/binary"
	"testing"
	"time"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/overlord/ifacestate/apparmorprompting/common"
	"github.com/snapcore/snapd/prompting/apparmor"
)

func Test(t *testing.T) { TestingT(t) }

type commonSuite struct {
	tmpdir string
}

var _ = Suite(&commonSuite{})

func (s *commonSuite) SetUpTest(c *C) {
	s.tmpdir = c.MkDir()
	dirs.SetRootDir(s.tmpdir)
}

func (s *commonSuite) TestRemovePermissionFromList(c *C) {
	cases := []struct {
		initial []common.PermissionType
		remove  common.PermissionType
		final   []common.PermissionType
		err     error
	}{
		{
			[]common.PermissionType{common.PermissionRead, common.PermissionWrite, common.PermissionExecute},
			common.PermissionRead,
			[]common.PermissionType{common.PermissionWrite, common.PermissionExecute},
			nil,
		},
		{
			[]common.PermissionType{common.PermissionRead, common.PermissionWrite, common.PermissionExecute},
			common.PermissionWrite,
			[]common.PermissionType{common.PermissionRead, common.PermissionExecute},
			nil,
		},
		{
			[]common.PermissionType{common.PermissionRead, common.PermissionWrite, common.PermissionExecute},
			common.PermissionExecute,
			[]common.PermissionType{common.PermissionRead, common.PermissionWrite},
			nil,
		},
		{
			[]common.PermissionType{common.PermissionRead, common.PermissionWrite, common.PermissionRead},
			common.PermissionRead,
			[]common.PermissionType{common.PermissionWrite},
			nil,
		},
		{
			[]common.PermissionType{common.PermissionRead},
			common.PermissionRead,
			[]common.PermissionType{},
			nil,
		},
		{
			[]common.PermissionType{common.PermissionRead, common.PermissionRead},
			common.PermissionRead,
			[]common.PermissionType{},
			nil,
		},
		{
			[]common.PermissionType{common.PermissionRead, common.PermissionWrite, common.PermissionExecute},
			common.PermissionAppend,
			[]common.PermissionType{common.PermissionRead, common.PermissionWrite, common.PermissionExecute},
			common.ErrPermissionNotInList,
		},
	}
	for _, testCase := range cases {
		result, err := common.RemovePermissionFromList(testCase.initial, testCase.remove)
		c.Assert(err, Equals, testCase.err)
		c.Assert(result, DeepEquals, testCase.final)
	}
}

func (s *commonSuite) TestTimestamps(c *C) {
	before := time.Now()
	ts := common.CurrentTimestamp()
	after := time.Now()
	parsedTime, err := common.TimestampToTime(ts)
	c.Assert(err, IsNil)
	c.Assert(parsedTime.After(before), Equals, true)
	c.Assert(parsedTime.Before(after), Equals, true)
}

func (s *commonSuite) TestNewIdAndTimestamp(c *C) {
	before := time.Now()
	id := common.NewId()
	idPaired, timestampPaired := common.NewIdAndTimestamp()
	after := time.Now()
	data1, err := base32.StdEncoding.DecodeString(id)
	c.Assert(err, IsNil)
	data2, err := base32.StdEncoding.DecodeString(idPaired)
	c.Assert(err, IsNil)
	parsedNs := int64(binary.BigEndian.Uint64(data1))
	parsedNsPaired := int64(binary.BigEndian.Uint64(data2))
	parsedTime := time.Unix(parsedNs/1000000000, parsedNs%1000000000)
	parsedTimePaired := time.Unix(parsedNsPaired/1000000000, parsedNsPaired%1000000000)
	c.Assert(parsedTime.After(before), Equals, true)
	c.Assert(parsedTime.Before(after), Equals, true)
	c.Assert(parsedTimePaired.After(before), Equals, true)
	c.Assert(parsedTimePaired.Before(after), Equals, true)
	parsedTimestamp, err := common.TimestampToTime(timestampPaired)
	c.Assert(err, IsNil)
	c.Assert(parsedTimePaired, Equals, parsedTimestamp)
}

func (s *commonSuite) TestLabelToSnapAppHappy(c *C) {
	cases := []struct {
		label string
		snap  string
		app   string
	}{
		{
			label: "snap.nextcloud.occ",
			snap:  "nextcloud",
			app:   "occ",
		},
		{
			label: "snap.lxd.lxc",
			snap:  "lxd",
			app:   "lxc",
		},
		{
			label: "snap.firefox.firefox",
			snap:  "firefox",
			app:   "firefox",
		},
	}
	for _, testCase := range cases {
		snap, app, err := common.LabelToSnapApp(testCase.label)
		c.Check(err, IsNil)
		c.Check(snap, Equals, testCase.snap)
		c.Check(app, Equals, testCase.app)
	}
}

func (s *commonSuite) TestLabelToSnapAppUnhappy(c *C) {
	cases := []string{
		"snap",
		"snap.nextcloud",
		"nextcloud.occ",
		"snap.nextcloud.nextcloud.occ",
		"SNAP.NEXTCLOUD.OCC",
	}
	for _, label := range cases {
		snap, app, err := common.LabelToSnapApp(label)
		c.Check(err, Equals, common.ErrInvalidSnapLabel)
		c.Check(snap, Equals, label)
		c.Check(app, Equals, label)
	}
}

func (s *commonSuite) TestPermissionMaskToPermissionsList(c *C) {
	cases := []struct {
		mask apparmor.FilePermission
		list []common.PermissionType
	}{
		{
			apparmor.FilePermission(0),
			[]common.PermissionType{},
		},
		{
			apparmor.MayExecutePermission,
			[]common.PermissionType{common.PermissionExecute},
		},
		{
			apparmor.MayWritePermission,
			[]common.PermissionType{common.PermissionWrite},
		},
		{
			apparmor.MayReadPermission,
			[]common.PermissionType{common.PermissionRead},
		},
		{
			apparmor.MayAppendPermission,
			[]common.PermissionType{common.PermissionAppend},
		},
		{
			apparmor.MayCreatePermission,
			[]common.PermissionType{common.PermissionCreate},
		},
		{
			apparmor.MayDeletePermission,
			[]common.PermissionType{common.PermissionDelete},
		},
		{
			apparmor.MayOpenPermission,
			[]common.PermissionType{common.PermissionOpen},
		},
		{
			apparmor.MayRenamePermission,
			[]common.PermissionType{common.PermissionRename},
		},
		{
			apparmor.MaySetAttrPermission,
			[]common.PermissionType{common.PermissionSetAttr},
		},
		{
			apparmor.MayGetAttrPermission,
			[]common.PermissionType{common.PermissionGetAttr},
		},
		{
			apparmor.MaySetCredentialPermission,
			[]common.PermissionType{common.PermissionSetCred},
		},
		{
			apparmor.MayGetCredentialPermission,
			[]common.PermissionType{common.PermissionGetCred},
		},
		{
			apparmor.MayChangeModePermission,
			[]common.PermissionType{common.PermissionChangeMode},
		},
		{
			apparmor.MayChangeOwnerPermission,
			[]common.PermissionType{common.PermissionChangeOwner},
		},
		{
			apparmor.MayChangeGroupPermission,
			[]common.PermissionType{common.PermissionChangeGroup},
		},
		{
			apparmor.MayLockPermission,
			[]common.PermissionType{common.PermissionLock},
		},
		{
			apparmor.MayExecuteMapPermission,
			[]common.PermissionType{common.PermissionExecuteMap},
		},
		{
			apparmor.MayLinkPermission,
			[]common.PermissionType{common.PermissionLink},
		},
		{
			apparmor.MayChangeProfileOnExecPermission,
			[]common.PermissionType{common.PermissionChangeProfileOnExec},
		},
		{
			apparmor.MayChangeProfilePermission,
			[]common.PermissionType{common.PermissionChangeProfile},
		},
		{
			apparmor.MayReadPermission | apparmor.MayWritePermission | apparmor.MayExecutePermission,
			[]common.PermissionType{common.PermissionExecute, common.PermissionWrite, common.PermissionRead},
		},
	}
	for _, testCase := range cases {
		perms, err := common.PermissionMaskToPermissionsList(testCase.mask)
		c.Assert(err, IsNil, Commentf("testCase: %+v", testCase))
		c.Assert(perms, DeepEquals, testCase.list)
	}

	unrecognizedFilePerm := apparmor.FilePermission(1 << 17)
	perms, err := common.PermissionMaskToPermissionsList(unrecognizedFilePerm)
	c.Assert(err, Equals, common.ErrUnrecognizedFilePermission)
	c.Assert(perms, HasLen, 0)

	mixed := unrecognizedFilePerm | apparmor.MayReadPermission | apparmor.MayWritePermission
	expected := []common.PermissionType{common.PermissionWrite, common.PermissionRead}
	perms, err = common.PermissionMaskToPermissionsList(mixed)
	c.Assert(err, Equals, common.ErrUnrecognizedFilePermission)
	c.Assert(perms, DeepEquals, expected)
}

func (s *commonSuite) TestPermissionsListContains(c *C) {
	permissionsList := []common.PermissionType{
		common.PermissionExecute,
		common.PermissionWrite,
		common.PermissionRead,
		common.PermissionAppend,
		common.PermissionOpen,
	}
	for _, perm := range []common.PermissionType{
		common.PermissionExecute,
		common.PermissionWrite,
		common.PermissionRead,
		common.PermissionAppend,
		common.PermissionOpen,
	} {
		c.Check(common.PermissionsListContains(permissionsList, perm), Equals, true)
	}
	for _, perm := range []common.PermissionType{
		common.PermissionCreate,
		common.PermissionDelete,
		common.PermissionRename,
		common.PermissionChangeOwner,
		common.PermissionChangeGroup,
	} {
		c.Check(common.PermissionsListContains(permissionsList, perm), Equals, false)
	}
}

func (s *commonSuite) TestValidatePathPattern(c *C) {
	for _, pattern := range []string{
		"/",
		"/*",
		"/**",
		"/**/*.txt",
		"/foo",
		"/foo",
		"/foo/file.txt",
		"/foo/bar",
		"/foo/bar/*",
		"/foo/bar/*.tar.gz",
		"/foo/bar/**",
		"/foo/bar/**/*.zip",
	} {
		c.Check(common.ValidatePathPattern(pattern), IsNil, Commentf("valid path pattern `%s` was incorrectly not allowed", pattern))
	}

	for _, pattern := range []string{
		"file.txt",
		"/**/*",
		"/foo/*/bar",
		"/foo/**/bar",
		"/foo/bar/",
		"/foo/bar*",
		"/foo/bar*.txt",
		"/foo/bar**",
		"/foo/bar/*txt",
		"/foo/bar/**.txt",
		"/foo/bar/*/file.txt",
		"/foo/bar/**/file.txt",
		"/foo/bar/**/*",
		"/foo/bar/**/*txt",
	} {
		c.Check(common.ValidatePathPattern(pattern), Equals, common.ErrInvalidPathPattern, Commentf("invalid path pattern `%s` was incorrectly allowed", pattern))
	}
}

func (s *commonSuite) TestValidateOutcome(c *C) {
	c.Assert(common.ValidateOutcome(common.OutcomeAllow), Equals, nil)
	c.Assert(common.ValidateOutcome(common.OutcomeDeny), Equals, nil)
	c.Assert(common.ValidateOutcome(common.OutcomeUnset), Equals, common.ErrInvalidOutcome)
	c.Assert(common.ValidateOutcome(common.OutcomeType("foo")), Equals, common.ErrInvalidOutcome)
}

func (s *commonSuite) TestValidateLifespanParseDuration(c *C) {
	unsetDuration := 0
	sampleDuration := 600
	sampleDurationAsTime := time.Duration(sampleDuration) * time.Second

	for _, lifespan := range []common.LifespanType{
		common.LifespanForever,
		common.LifespanSession,
		common.LifespanSingle,
	} {
		expiration, err := common.ValidateLifespanParseDuration(lifespan, unsetDuration)
		c.Check(expiration, Equals, "")
		c.Check(err, IsNil)
		expiration, err = common.ValidateLifespanParseDuration(lifespan, sampleDuration)
		c.Check(expiration, Equals, "")
		c.Check(err, Equals, common.ErrInvalidDuration)
	}

	expiration, err := common.ValidateLifespanParseDuration(common.LifespanTimespan, unsetDuration)
	c.Check(expiration, Equals, "")
	c.Check(err, Equals, common.ErrInvalidDuration)

	expiration, err = common.ValidateLifespanParseDuration(common.LifespanTimespan, sampleDuration)
	c.Check(err, Equals, nil)
	expirationTime, err := time.Parse(time.RFC3339, expiration)
	c.Check(err, IsNil)
	c.Check(expirationTime.After(time.Now()), Equals, true)
	c.Check(expirationTime.Before(time.Now().Add(sampleDurationAsTime)), Equals, true)
}

func (s *commonSuite) TestGetHighestPrecedencePattern(c *C) {
	for i, testCase := range []struct {
		Patterns          []string
		HighestPrecedence string
	}{
		{
			[]string{
				"/foo",
			},
			"/foo",
		},
		{
			[]string{
				"/foo",
				"/foo/*",
			},
			"/foo",
		},
		{
			[]string{
				"/foo",
				"/foo/**",
			},
			"/foo",
		},
		{
			[]string{
				"/foo/*",
				"/foo/**",
			},
			"/foo/*",
		},
		{
			[]string{
				"/foo/**",
				"/foo/*",
			},
			"/foo/*",
		},
		{
			[]string{
				"/foo",
				"/foo/*",
				"/foo/**",
			},
			"/foo",
		},
		{
			[]string{
				"/foo/*",
				"/foo/bar",
			},
			"/foo/bar",
		},
		{
			[]string{
				"/foo/**",
				"/foo/bar",
			},
			"/foo/bar",
		},
		{
			[]string{
				"/foo/**",
				"/foo/bar/*",
			},
			"/foo/bar/*",
		},
		{
			[]string{
				"/foo/bar/**",
				"/foo/**",
			},
			"/foo/bar/**",
		},
		{
			[]string{
				"/foo/**",
				"/foo/bar/file.txt",
			},
			"/foo/bar/file.txt",
		},
		{
			[]string{
				"/foo/**/*.txt",
				"/foo/bar/**",
			},
			"/foo/**/*.txt",
		},
		{
			[]string{
				"/foo/**/*.gz",
				"/foo/**/*.tar.gz",
			},
			"/foo/**/*.tar.gz",
		},
		{
			[]string{
				"/foo/bar/**/*.gz",
				"/foo/**/*.tar.gz",
			},
			"/foo/**/*.tar.gz",
		},
	} {
		highestPrecedence, err := common.GetHighestPrecedencePattern(testCase.Patterns)
		c.Check(err, IsNil, Commentf("Error occurred during test case %d:\n%+v", i, testCase))
		c.Check(highestPrecedence, Equals, testCase.HighestPrecedence, Commentf("Highest precedence pattern incorrect for test case %d:\n%+v", i, testCase))
	}

	empty, err := common.GetHighestPrecedencePattern([]string{})
	c.Check(err, Equals, common.ErrNoPatterns)
	c.Check(empty, Equals, "")
}

func (*commonSuite) TestPathPatternMatches(c *C) {
	cases := []struct {
		pattern string
		path    string
		matches bool
	}{
		{
			"/home/test/Documents/foo.txt",
			"/home/test/Documents/foo.txt",
			true,
		},
		{
			"/home/test/Documents/foo",
			"/home/test/Documents/foo.txt",
			false,
		},
		{
			"/home/test/Documents/*",
			"/home/test/Documents/foo.txt",
			true,
		},
		{
			"/home/test/Documents/**",
			"/home/test/Documents/foo.txt",
			true,
		},
		{
			"/home/test/Documents/**/*.txt",
			"/home/test/Documents/foo.txt",
			true,
		},
		{
			"/home/test/Documents/**/*.txt",
			"/home/test/Documents/foo/bar.tar.gz",
			false,
		},
		{
			"/home/test/Documents/**",
			"/home/test/Documents/foo/bar.tar.gz",
			true,
		},
		{
			"/home/test/Documents/**/*.gz",
			"/home/test/Documents/foo/bar.tar.gz",
			true,
		},
		{
			"/home/test/Documents/**/*.tar.gz",
			"/home/test/Documents/foo/bar.tar.gz",
			true,
		},
		{
			"/home/test/Documents/*.tar.gz",
			"/home/test/Documents/foo/bar.tar.gz",
			false,
		},
		{
			"/home/test/Documents/*",
			"/home/test/Documents/foo/bar.tar.gz",
			false,
		},
		{
			"/home/test/**",
			"/home/test/Documents/foo/bar.tar.gz",
			true,
		},
		{
			"/home/test/*",
			"/home/test/Documents/foo/bar.tar.gz",
			false,
		},
		{
			"/home/test/**/*.tar.gz",
			"/home/test/Documents/foo/bar.tar.gz",
			true,
		},
		{
			"/home/test/**/*.gz",
			"/home/test/Documents/foo/bar.tar.gz",
			true,
		},
		{
			"/home/test/**/*.txt",
			"/home/test/Documents/foo/bar.tar.gz",
			false,
		},
	}
	for _, testCase := range cases {
		result, err := common.PathPatternMatches(testCase.pattern, testCase.path)
		c.Check(err, IsNil, Commentf("test case: %+v", testCase))
		c.Check(result, Equals, testCase.matches, Commentf("test case: %+v", testCase))
	}
}