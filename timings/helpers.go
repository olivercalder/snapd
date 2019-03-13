// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2019 Canonical Ltd
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

package timings

import (
	"github.com/snapcore/snapd/overlord/state"
)

// NewForTask creates a new Timings tree for given task and starts a
// measurement (Span) for it. Returned Timings tree has "task-id" and "change-id"
// tags set automatically from the respective task.
func NewForTask(task *state.Task) (*Timings, *Span) {
	tags := map[string]string{"task-id": task.ID()}
	if chg := task.Change(); chg != nil {
		tags["change-id"] = chg.ID()
	}
	t := New(tags)
	return t, t.StartSpan(task.Kind(), task.Summary())
}

// Run creates, starts and then stops a nested Span under parent span. The nested
// Span is passed to the measured function and it can used to create further spans.
func (t *Span) Run(label, summary string, f func(nestedTiming *Span)) {
	meas := t.StartSpan(label, summary)
	f(meas)
	meas.Stop()
}
