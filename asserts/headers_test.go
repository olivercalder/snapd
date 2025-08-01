// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2015 Canonical Ltd
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

package asserts_test

import (
	"bytes"

	. "gopkg.in/check.v1"

	"github.com/snapcore/snapd/asserts"
)

type headersSuite struct{}

var _ = Suite(&headersSuite{})

func (s *headersSuite) TestParseHeadersSimple(c *C) {
	m, err := asserts.ParseHeaders([]byte(`foo: 1
bar: baz`))
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"foo": "1",
		"bar": "baz",
	})
}

func (s *headersSuite) TestParseHeadersMultiline(c *C) {
	m, err := asserts.ParseHeaders([]byte(`foo:
    abc
    
bar: baz`))
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"foo": "abc\n",
		"bar": "baz",
	})

	m, err = asserts.ParseHeaders([]byte(`foo: 1
bar:
    baz`))
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"foo": "1",
		"bar": "baz",
	})

	m, err = asserts.ParseHeaders([]byte(`foo: 1
bar:
    baz
    `))
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"foo": "1",
		"bar": "baz\n",
	})

	m, err = asserts.ParseHeaders([]byte(`foo: 1
bar:
    baz
    
    baz2`))
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"foo": "1",
		"bar": "baz\n\nbaz2",
	})
}

func (s *headersSuite) TestParseHeadersSimpleList(c *C) {
	m, err := asserts.ParseHeaders([]byte(`foo:
  - x
  - y
  - z
bar: baz`))
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"foo": []any{"x", "y", "z"},
		"bar": "baz",
	})
}

func (s *headersSuite) TestParseHeadersListNestedMultiline(c *C) {
	m, err := asserts.ParseHeaders([]byte(`foo:
  - x
  -
      y1
      y2
      
  - z
bar: baz`))
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"foo": []any{"x", "y1\ny2\n", "z"},
		"bar": "baz",
	})

	m, err = asserts.ParseHeaders([]byte(`bar: baz
foo:
  -
    - u1
    - u2
  -
      y1
      y2
      `))
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"foo": []any{[]any{"u1", "u2"}, "y1\ny2\n"},
		"bar": "baz",
	})
}

func (s *headersSuite) TestParseHeadersSimpleMap(c *C) {
	m, err := asserts.ParseHeaders([]byte(`foo:
  x: X
  yy: YY
  z5: 
bar: baz`))
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"foo": map[string]any{
			"x":  "X",
			"yy": "YY",
			"z5": "",
		},
		"bar": "baz",
	})
}

func (s *headersSuite) TestParseHeadersMapNestedMultiline(c *C) {
	m, err := asserts.ParseHeaders([]byte(`foo:
  x: X
  yy:
      YY1
      YY2
  u:
    - u1
    - u2
bar: baz`))
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"foo": map[string]any{
			"x":  "X",
			"yy": "YY1\nYY2",
			"u":  []any{"u1", "u2"},
		},
		"bar": "baz",
	})

	m, err = asserts.ParseHeaders([]byte(`one:
  two:
    three: `))
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"one": map[string]any{
			"two": map[string]any{
				"three": "",
			},
		},
	})

	m, err = asserts.ParseHeaders([]byte(`one:
  two:
      three`))
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"one": map[string]any{
			"two": "three",
		},
	})

	m, err = asserts.ParseHeaders([]byte(`map-within-map:
  lev1:
    lev2: x`))
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"map-within-map": map[string]any{
			"lev1": map[string]any{
				"lev2": "x",
			},
		},
	})

	m, err = asserts.ParseHeaders([]byte(`list-of-maps:
  -
    entry: foo
    bar: baz
  -
    entry: bar`))
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"list-of-maps": []any{
			map[string]any{
				"entry": "foo",
				"bar":   "baz",
			},
			map[string]any{
				"entry": "bar",
			},
		},
	})
}

func (s *headersSuite) TestParseHeadersMapErrors(c *C) {
	_, err := asserts.ParseHeaders([]byte(`foo:
  x X
bar: baz`))
	c.Check(err, ErrorMatches, `map entry missing ':' separator: "x X"`)

	_, err = asserts.ParseHeaders([]byte(`foo:
  0x: X
bar: baz`))
	c.Check(err, ErrorMatches, `invalid map entry key: "0x"`)

	_, err = asserts.ParseHeaders([]byte(`foo:
  a: a
  a: b`))
	c.Check(err, ErrorMatches, `repeated map entry: "a"`)
}

func (s *headersSuite) TestParseHeadersErrors(c *C) {
	_, err := asserts.ParseHeaders([]byte(`foo: 1
bar:baz`))
	c.Check(err, ErrorMatches, `header entry should have a space or newline \(for multiline\) before value: "bar:baz"`)

	_, err = asserts.ParseHeaders([]byte(`foo:
 - x
  - y
  - z
bar: baz`))
	c.Check(err, ErrorMatches, `expected 4 chars nesting prefix after multiline introduction "foo:": " - x"`)

	_, err = asserts.ParseHeaders([]byte(`foo:
  - x
  - y
  - z
bar:`))
	c.Check(err, ErrorMatches, `expected 4 chars nesting prefix after multiline introduction "bar:": EOF`)
}

func (s *headersSuite) TestAppendEntrySimple(c *C) {
	buf := bytes.NewBufferString("start: .")

	asserts.AppendEntry(buf, "bar:", "baz", 0)

	m, err := asserts.ParseHeaders(buf.Bytes())
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"start": ".",
		"bar":   "baz",
	})
}

func (s *headersSuite) TestAppendEntryMultiline(c *C) {
	multilines := []string{
		"a\n",
		"a\nb",
		"baz\n baz1\nbaz2",
		"baz\n baz1\nbaz2\n",
		"baz\n baz1\nbaz2\n\n",
	}

	for _, multiline := range multilines {
		buf := bytes.NewBufferString("start: .")

		asserts.AppendEntry(buf, "bar:", multiline, 0)

		m, err := asserts.ParseHeaders(buf.Bytes())
		c.Assert(err, IsNil)
		c.Check(m, DeepEquals, map[string]any{
			"start": ".",
			"bar":   multiline,
		})
	}
}

func (s *headersSuite) TestAppendEntrySimpleList(c *C) {
	lst := []any{"x", "y", "z"}

	buf := bytes.NewBufferString("start: .")

	asserts.AppendEntry(buf, "bar:", lst, 0)

	m, err := asserts.ParseHeaders(buf.Bytes())
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"start": ".",
		"bar":   lst,
	})
}

func (s *headersSuite) TestAppendEntryListNested(c *C) {
	lst := []any{"x", "a\nb\n", "", []any{"u1", []any{"w1", "w2"}}}

	buf := bytes.NewBufferString("start: .")

	asserts.AppendEntry(buf, "bar:", lst, 0)

	m, err := asserts.ParseHeaders(buf.Bytes())
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"start": ".",
		"bar":   lst,
	})
}

func (s *headersSuite) TestAppendEntrySimpleMap(c *C) {
	mp := map[string]any{
		"x":  "X",
		"yy": "YY",
		"z5": "",
	}

	buf := bytes.NewBufferString("start: .")

	asserts.AppendEntry(buf, "bar:", mp, 0)

	m, err := asserts.ParseHeaders(buf.Bytes())
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"start": ".",
		"bar":   mp,
	})
}

func (s *headersSuite) TestAppendEntryNestedMap(c *C) {
	mp := map[string]any{
		"x":  "X",
		"u":  []any{"u1", "u2"},
		"yy": "YY1\nYY2",
		"m":  map[string]any{"a": "A", "b": map[string]any{"x": "X", "y": "Y"}},
	}

	buf := bytes.NewBufferString("start: .")

	asserts.AppendEntry(buf, "bar:", mp, 0)

	m, err := asserts.ParseHeaders(buf.Bytes())
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"start": ".",
		"bar":   mp,
	})
}

func (s *headersSuite) TestAppendEntryOmitting(c *C) {
	buf := bytes.NewBufferString("start: .")

	asserts.AppendEntry(buf, "bar:", []any{}, 0)

	m, err := asserts.ParseHeaders(buf.Bytes())
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"start": ".",
	})

	lst := []any{nil, []any{}, "z"}

	buf = bytes.NewBufferString("start: .")

	asserts.AppendEntry(buf, "bar:", lst, 0)

	m, err = asserts.ParseHeaders(buf.Bytes())
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"start": ".",
		"bar":   []any{"z"},
	})

	buf = bytes.NewBufferString("start: .")

	asserts.AppendEntry(buf, "bar:", map[string]any{}, 0)

	m, err = asserts.ParseHeaders(buf.Bytes())
	c.Assert(err, IsNil)
	c.Check(m, DeepEquals, map[string]any{
		"start": ".",
	})
}
