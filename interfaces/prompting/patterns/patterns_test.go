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

package patterns_test

import (
	"strings"
	"testing"

	. "gopkg.in/check.v1"

	doublestar "github.com/bmatcuk/doublestar/v4"

	"github.com/snapcore/snapd/interfaces/prompting/patterns"
)

func Test(t *testing.T) { TestingT(t) }

type patternsSuite struct{}

var _ = Suite(&patternsSuite{})

func (s *patternsSuite) TestParsePathPatternHappy(c *C) {
	for _, pattern := range []string{
		"/",
		"/*",
		"/**",
		"/**/*.txt",
		"/foo",
		"/foo/",
		"/foo/file.txt",
		"/foo*",
		"/foo*bar",
		"/foo*bar/baz",
		"/foo/bar*baz",
		"/foo/*",
		"/foo/*bar",
		"/foo/*bar/",
		"/foo/*bar/baz",
		"/foo/*bar/baz/",
		"/foo/*/",
		"/foo/*/bar",
		"/foo/*/bar/",
		"/foo/*/bar/baz",
		"/foo/*/bar/baz/",
		"/foo/**/bar",
		"/foo/**/bar/",
		"/foo/**/bar/baz",
		"/foo/**/bar/baz/",
		"/foo/**/bar*",
		"/foo/**/bar*baz",
		"/foo/**/bar*baz/",
		"/foo/**/bar*/",
		"/foo/**/bar*/baz",
		"/foo/**/bar*/baz/fizz/",
		"/foo/**/bar/*",
		"/foo/**/bar/*.tar.gz",
		"/foo/**/bar/*baz",
		"/foo/**/bar/*baz/fizz/",
		"/foo/**/bar/*/",
		"/foo/**/bar/*baz",
		"/foo/**/bar/buzz/*baz/",
		"/foo/**/bar/*baz/fizz",
		"/foo/**/bar/buzz/*baz/fizz/",
		"/foo/**/bar/*/baz",
		"/foo/**/bar/buzz/*/baz/",
		"/foo/**/bar/*/baz/fizz",
		"/foo/**/bar/buzz/*/baz/fizz/",
		"/foo/**/bar/buzz*baz/fizz/",
		"/foo/**/*bar",
		"/foo/**/*bar/",
		"/foo/**/*bar/baz.tar.gz",
		"/foo/**/*bar/baz/",
		"/foo/**/*/",
		"/foo/**/*/bar",
		"/foo/**/*/bar/baz/",
		"/foo{,/,bar,*baz,*.baz,/*fizz,/*.fizz,/**/*buzz}",
		"/foo/{,*.bar,**/baz}",
		"/foo/bar/*",
		"/foo/bar/*.tar.gz",
		"/foo/bar/**",
		"/foo/bar/**/*.zip",
		"/foo/bar/**/*.tar.gz",
		`/foo/bar\,baz`,
		`/foo/bar\{baz`,
		`/foo/bar\\baz`,
		`/foo/bar\*baz`,
		`/foo/bar{,/baz/*,/fizz/**/*.txt}`,
		"/foo/*/bar",
		"/foo/bar/",
		"/foo/**/bar",
		"/foo/bar*",
		"/foo/bar*.txt",
		"/foo/bar/*txt",
		"/foo/bar/**/file.txt",
		"/foo/bar/*/file.txt",
		"/foo/bar/**/*txt",
		"/foo/bar**",
		"/foo/bar/**.txt",
		"/foo/ba,r",
		"/foo/ba,r/**/*.txt",
		"/foo/bar/**/*.txt,md",
		"/foo//bar",
		"/foo{//,bar}",
		"/foo{//*.bar,baz}",
		"/foo/{/*.bar,baz}",
		"/foo/*/**",
		"/foo/*/bar/**",
		"/foo/*/bar/*",
		"/foo{bar,/baz}{fizz,buzz}",
		"/foo{bar,/baz}/{fizz,buzz}",
		"/foo?bar",
		"/foo/{a,b}{c,d}{e,f}{g,h}{i,j}{k,l}{m,n}{o,p}{q,r}", // expands to 512
		"/foo/{a,{b,{c,{d,{e,{f,{g,{h,{i,{j,{k,{l,{m,{n,{o,p}}}}}}}}}}}}}}}",
		"/foo/{{{{{{{{{{{{{{{a,b},c},d},e},f},g},h},i},j},k},l},m},n},o},p}",
		"/foo/{a,b}{c,d}{e,f}{g,h,i,j,k}{l,m,n,o,p}{q,r,s,t,u}",       // expands to 1000
		"/foo/{a,b}{c,d}{e,f}{g,h,i,j,k}{l,m,n,o,p}{q,r,s,t,u},1,2,3", // expands to 1000, with commas outside groups
		"/" + strings.Repeat("{a,", 999) + "a" + strings.Repeat("}", 999),
		"/" + strings.Repeat("{", 999) + "a" + strings.Repeat(",a}", 999),
	} {
		_, err := patterns.ParsePathPattern(pattern)
		c.Check(err, IsNil, Commentf("valid path pattern %q was incorrectly not allowed", pattern))
	}
}

func (s *patternsSuite) TestParsePathPatternUnhappy(c *C) {
	for _, testCase := range []struct {
		pattern string
		errStr  string
	}{
		{
			``,
			`cannot parse path pattern .*: pattern has length 0`,
		},
		{
			`file.txt`,
			`cannot parse path pattern "file.txt": pattern must start with '/'`,
		},
		{
			`{/,/foo}`,
			`cannot parse path pattern .*: pattern must start with '/'`,
		},
		{
			`/foo{bar`,
			`cannot parse path pattern .*: unmatched '{' character`,
		},
		{
			`/foo}bar`,
			`cannot parse path pattern .*: unmatched '}' character.*`,
		},
		{
			`/foo/bar\`,
			`cannot parse path pattern .*: trailing unescaped '\\' character`,
		},
		{
			`/foo/bar{`,
			`cannot parse path pattern .*: unmatched '{' character`,
		},
		{
			`/foo/bar{baz\`,
			`cannot parse path pattern .*: trailing unescaped '\\' character`,
		},
		{
			`/foo/bar{baz{\`,
			`cannot parse path pattern .*: trailing unescaped '\\' character`,
		},
		{
			`/foo/bar{baz{`,
			`cannot parse path pattern .*: unmatched '{' character`,
		},
		{
			`/foo/ba[rz]`,
			`cannot parse path pattern .*: cannot contain unescaped '\[' or '\]' character`,
		},
		{
			`/foo/{a,b}{c,d}{e,f}{g,h}{i,j}{k,l}{m,n}{o,p}{q,r}{s,t}`, // expands to 1024
			`cannot parse path pattern .*: exceeded maximum number of expanded path patterns \(1000\): 1024`,
		},
		{
			`/foo/{a,b,c,d,e,f,g}{h,i,j,k,l,m,n,o,p,q,r}{s,t,u,v,w,x,y,z,1,2,3,4,5}`, // expands to 1001
			`cannot parse path pattern .*: exceeded maximum number of expanded path patterns \(1000\): 1001`,
		},
		{
			"/" + strings.Repeat("{a,", 1000) + "a" + strings.Repeat("}", 1000),
			`cannot parse path pattern .*: nested group depth exceeded maximum number of expanded path patterns \(1000\)`,
		},
		{
			"/" + strings.Repeat("{", 1000) + "a" + strings.Repeat(",a}", 1000),
			`cannot parse path pattern .*: nested group depth exceeded maximum number of expanded path patterns \(1000\)`,
		},
		{
			"/" + strings.Repeat("{", 10000),
			`cannot parse path pattern .*: nested group depth exceeded maximum number of expanded path patterns \(1000\)`,
		},
	} {
		pathPattern, err := patterns.ParsePathPattern(testCase.pattern)
		c.Check(err, ErrorMatches, testCase.errStr, Commentf("testCase: %+v", testCase))
		c.Check(pathPattern, IsNil)
	}
}

func (s *patternsSuite) TestPathPatternString(c *C) {
	for _, pattern := range []string{
		"/foo",
		"/foo/ba{r,s}/**",
		"/{a,b}{c,d}{e,f}{g,h}",
	} {
		pathPattern, err := patterns.ParsePathPattern(pattern)
		c.Check(err, IsNil)
		c.Check(pathPattern.String(), Equals, pattern)
	}
}

func (s *patternsSuite) TestPathPatternMarshalJSON(c *C) {
	for _, pattern := range []string{
		"/foo",
		"/foo/ba{r,s}/**",
		"/{a,b}{c,d}{e,f}{g,h}",
	} {
		pathPattern, err := patterns.ParsePathPattern(pattern)
		c.Check(err, IsNil)
		marshalled, err := pathPattern.MarshalJSON()
		c.Check(err, IsNil)
		c.Check(marshalled, DeepEquals, []byte(pattern))
	}
}

func (s *patternsSuite) TestPathPatternUnmarshalJSONHappy(c *C) {
	for _, pattern := range [][]byte{
		[]byte(`"/foo"`),
		[]byte(`"/foo/ba{r,s}/**"`),
		[]byte(`"/{a,b}{c,d}{e,f}{g,h}"`),
	} {
		pathPattern := patterns.PathPattern{}
		err := pathPattern.UnmarshalJSON(pattern)
		c.Check(err, IsNil)
		marshalled, err := pathPattern.MarshalJSON()
		c.Check(err, IsNil)
		// Marshalled pattern excludes surrounding '"' for some reason
		c.Check(marshalled, DeepEquals, pattern[1:len(pattern)-1])
	}
}

func (s *patternsSuite) TestPathPatternUnmarshalJSONUnhappy(c *C) {
	for _, testCase := range []struct {
		json []byte
		err  string
	}{
		{
			[]byte(`"foo"`),
			`cannot parse path pattern "foo": pattern must start with '/'.*`,
		},
		{
			[]byte{'"', 0x00, '"'},
			`invalid character '\\x00' in string literal`,
		},
	} {
		pathPattern := patterns.PathPattern{}
		err := pathPattern.UnmarshalJSON(testCase.json)
		c.Check(err, ErrorMatches, testCase.err)
	}
}

func (s *patternsSuite) TestPathPatternRenderAllVariants(c *C) {
	for _, testCase := range []struct {
		pattern  string
		expanded []string
	}{
		{
			`/foo`,
			[]string{`/foo`},
		},
		{
			`/{foo,bar/}`,
			[]string{`/foo`, `/bar/`},
		},
		{
			`/{/foo,/bar/}`,
			[]string{`/foo`, `/bar/`},
		},
		{
			`/foo**/bar/*/**baz/**/fizz*buzz/**`,
			[]string{`/foo*/bar/*/*baz/**/fizz*buzz/**`},
		},
		{
			`/{,//foo**/bar/*/**baz/**/fizz*buzz/**}`,
			[]string{`/`, `/foo*/bar/*/*baz/**/fizz*buzz/**`},
		},
		{
			`/{foo,bar,/baz}`,
			[]string{`/foo`, `/bar`, `/baz`},
		},
		{
			`/{foo,/bar,bar,/baz}`,
			[]string{`/foo`, `/bar`, `/bar`, `/baz`},
		},
		{
			`/foo/bar\**baz`,
			[]string{`/foo/bar\**baz`},
		},
		{
			`/foo/bar\{baz`,
			[]string{`/foo/bar\{baz`},
		},
		{
			`/foo/bar\}baz`,
			[]string{`/foo/bar\}baz`},
		},
		{
			`/foo/bar/baz/**/*.txt`,
			[]string{`/foo/bar/baz/**/*.txt`},
		},
		{
			`/foo/bar/baz/***.txt`,
			[]string{`/foo/bar/baz/*.txt`},
		},
		{
			`/foo/bar/baz******.txt`,
			[]string{`/foo/bar/baz*.txt`},
		},
		{
			`/foo/bar/baz/{?***,*?**,**?*,***?}.txt`,
			[]string{`/foo/bar/baz/?*.txt`, `/foo/bar/baz/?*.txt`, `/foo/bar/baz/?*.txt`, `/foo/bar/baz/?*.txt`},
		},
		{
			`/foo/bar/baz/{?***?,*?**?,**?*?,***??}.txt`,
			[]string{`/foo/bar/baz/??*.txt`, `/foo/bar/baz/??*.txt`, `/foo/bar/baz/??*.txt`, `/foo/bar/baz/??*.txt`},
		},
		{
			`/foo/bar/baz/{?***??,*?**??,**?*??,***???}.txt`,
			[]string{`/foo/bar/baz/???*.txt`, `/foo/bar/baz/???*.txt`, `/foo/bar/baz/???*.txt`, `/foo/bar/baz/???*.txt`},
		},
		{
			`/foo///bar/**/**/**/baz/***.txt/**/**/*`,
			[]string{`/foo/bar/**/baz/*.txt/**`},
		},
		{
			`/{a,b}c{d,e}f{g,h}`,
			[]string{
				`/acdfg`,
				`/acdfh`,
				`/acefg`,
				`/acefh`,
				`/bcdfg`,
				`/bcdfh`,
				`/bcefg`,
				`/bcefh`,
			},
		},
		{
			`/a{{b,c},d,{e{f,{,g}}}}h`,
			[]string{
				`/abh`,
				`/ach`,
				`/adh`,
				`/aefh`,
				`/aeh`,
				`/aegh`,
			},
		},
		{
			`/a{{b,c},d,\{e{f,{,g\}}}}h`,
			[]string{
				`/abh`,
				`/ach`,
				`/adh`,
				`/a\{efh`,
				`/a\{eh`,
				`/a\{eg\}h`,
			},
		},
		{
			"/foo/{a,{b,{c,{d,{e,{f,{g,{h,{i,{j,k}}}}}}}}}}",
			[]string{
				"/foo/a",
				"/foo/b",
				"/foo/c",
				"/foo/d",
				"/foo/e",
				"/foo/f",
				"/foo/g",
				"/foo/h",
				"/foo/i",
				"/foo/j",
				"/foo/k",
			},
		},
		{
			"/foo/{{{{{{{{{{a,b},c},d},e},f},g},h},i},j},k}",
			[]string{
				"/foo/a",
				"/foo/b",
				"/foo/c",
				"/foo/d",
				"/foo/e",
				"/foo/f",
				"/foo/g",
				"/foo/h",
				"/foo/i",
				"/foo/j",
				"/foo/k",
			},
		},
		{
			"/foo,bar,baz",
			[]string{"/foo,bar,baz"},
		},
	} {
		pathPattern, err := patterns.ParsePathPattern(testCase.pattern)
		c.Check(err, IsNil, Commentf("testcase: %+v", testCase))
		expanded := make([]string, 0, pathPattern.NumVariants())
		pathPattern.RenderAllVariants(func(i int, str string) {
			expanded = append(expanded, str)
		})
		c.Check(expanded, DeepEquals, testCase.expanded, Commentf("test case: %+v", testCase))
	}
}

func (s *patternsSuite) TestPathPatternMatch(c *C) {
	cases := []struct {
		pattern string
		path    string
		matches bool
	}{
		{
			"/home/test/Documents",
			"/home/test/Documents",
			true,
		},
		{
			"/home/test/Documents",
			"/home/test/Documents/",
			true,
		},
		{
			"/home/test/Documents/",
			"/home/test/Documents",
			false,
		},
		{
			"/home/test/Documents/",
			"/home/test/Documents/",
			true,
		},
		{
			"/home/test/Documents/*",
			"/home/test/Documents",
			false,
		},
		{
			"/home/test/Documents/*",
			"/home/test/Documents/",
			true,
		},
		{
			"/home/test/Documents/*",
			"/home/test/Documents/foo",
			true,
		},
		{
			"/home/test/Documents/*",
			"/home/test/Documents/foo/",
			true,
		},
		{
			"/home/test/Documents/*/",
			"/home/test/Documents",
			false,
		},
		{
			"/home/test/Documents/*/",
			"/home/test/Documents/",
			false,
		},
		{
			"/home/test/Documents/*/",
			"/home/test/Documents/foo",
			false,
		},
		{
			"/home/test/Documents/*/",
			"/home/test/Documents/foo/",
			true,
		},
		{
			"/home/test/Documents/**",
			"/home/test/Documents",
			true,
		},
		{
			"/home/test/Documents/**",
			"/home/test/Documents/",
			true,
		},
		{
			"/home/test/Documents/**",
			"/home/test/Documents/foo",
			true,
		},
		{
			"/home/test/Documents/**",
			"/home/test/Documents/foo/",
			true,
		},
		{
			// Even though doublestar lets /path/to/a/**/ match /path/to/a, we
			// want the ability to match only directories, so we impose the
			// additional constraint that patterns ending in /**/ only match
			// paths which end in /
			"/home/test/Documents/**/",
			"/home/test/Documents",
			false,
		},
		{
			"/home/test/Documents/**/",
			"/home/test/Documents/",
			true,
		},
		{
			"/home/test/Documents/**/",
			"/home/test/Documents/foo",
			false,
		},
		{
			"/home/test/Documents/**/",
			"/home/test/Documents/foo/",
			true,
		},
		{
			"/home/test/Documents/**/",
			"/home/test/Documents/foo/bar",
			false,
		},
		{
			"/home/test/Documents/**/",
			"/home/test/Documents/foo/bar/",
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
			"/home/test/Documents/foo",
			"/home/test/Documents/foo.txt",
			false,
		},
		{
			"/home/test/Documents/foo*",
			"/home/test/Documents/foo.txt",
			true,
		},
		{
			"/home/test/Documents/foo?*",
			"/home/test/Documents/foo.txt",
			true,
		},
		{
			"/home/test/Documents/foo????",
			"/home/test/Documents/foo.txt",
			true,
		},
		{
			"/home/test/Documents/foo????*",
			"/home/test/Documents/foo.txt",
			true,
		},
		{
			"/home/test/Documents/foo?????*",
			"/home/test/Documents/foo.txt",
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
		{
			"/foo/bar*",
			"/hoo/bar/",
			false,
		},
		{
			"/foo/bar?",
			"/hoo/bar/",
			false,
		},
		{
			"/foo/bar/**",
			"/foo/bar/",
			true,
		},
		{
			"/foo/*/bar/**/baz**/fi*z/**buzz",
			"/foo/abc/bar/baznm/fizz/xyzbuzz",
			true,
		},
		{
			"/foo/*/bar/**/baz**/fi*z/**buzz",
			"/foo/abc/bar/baz/nm/fizz/xyzbuzz",
			false,
		},
		{
			"/foo*bar",
			"/foobar",
			true,
		},
		{
			"/foo*bar",
			"/fooxbar",
			true,
		},
		{
			"/foo*bar",
			"/foo/bar",
			false,
		},
		{
			"/foo?bar",
			"/foobar",
			false,
		},
		{
			"/foo?bar",
			"/fooxbar",
			true,
		},
		{
			"/foo?bar",
			"/foo/bar",
			false,
		},
		{
			"/foo/*/bar",
			"/foo/bar",
			false,
		},
		{
			"/foo/**/bar",
			"/foo/bar",
			true,
		},
		{
			"/foo/**/bar",
			"/foo/bar/",
			true,
		},
		{
			"/foo/**/bar",
			"/foo/fizz/buzz/bar/",
			true,
		},
		{
			"/foo**/bar",
			"/fooabc/bar",
			true,
		},
		{
			"/foo**/bar",
			"/foo/bar",
			true,
		},
		{
			"/foo**/bar",
			"/foo/fizz/bar",
			false,
		},
		{
			"/foo/**bar",
			"/foo/abcbar",
			true,
		},
		{
			"/foo/**bar",
			"/foo/bar",
			true,
		},
		{
			"/foo/**bar",
			"/foo/fizz/bar",
			false,
		},
		{
			"/foo/*/bar/**/baz**/fi*z/**buzz",
			"/foo/abc/bar/baz/fiz/buzz",
			true,
		},
		{
			"/foo/*/bar/**/baz**/fi*z/**buzz",
			"/foo/abc/bar/baz/abc/fiz/buzz",
			false,
		},
		{
			"/foo/*/bar/**/baz**/fi*z/**buzz",
			"/foo/bar/bazmn/fizz/xyzbuzz",
			false,
		},
		{
			"/foo/bar/**/*/",
			"/foo/bar/baz",
			false,
		},
		{
			"/foo/bar/**/*/",
			"/foo/bar/baz/",
			true,
		},
	}
	for _, testCase := range cases {
		matches, err := patterns.PathPatternMatch(testCase.pattern, testCase.path)
		c.Check(err, IsNil, Commentf("test case: %+v", testCase))
		c.Check(matches, Equals, testCase.matches, Commentf("test case: %+v", testCase))
	}
}

func (s *patternsSuite) TestPathPatternMatchErrors(c *C) {
	badPattern := `badpattern\`
	matches, err := patterns.PathPatternMatch(badPattern, "foo")
	c.Check(err, Equals, doublestar.ErrBadPattern)
	c.Check(matches, Equals, false)
}
