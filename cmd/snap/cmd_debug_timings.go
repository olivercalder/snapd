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

package main

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jessevdk/go-flags"

	"github.com/snapcore/snapd/client"
	"github.com/snapcore/snapd/i18n"
)

type cmdChangeTimings struct {
	changeIDMixin
	EnsureTag string `long:"ensure"`
	All       bool   `long:"all"`
	Verbose   bool   `long:"verbose"`
}

func init() {
	addDebugCommand("timings",
		i18n.G("Get the timings of the tasks of a change"),
		i18n.G("The timings command displays details about the time each task runs."),
		func() flags.Commander {
			return &cmdChangeTimings{}
		}, changeIDMixinOptDesc.also(map[string]string{
			"ensure": i18n.G("Show timings for a change related to the given Ensure activity"),
			"all":    i18n.G("Show timings for all executions of the given Ensure activity, not just the latest"),
			// TRANSLATORS: This should not start with a lowercase letter.
			"verbose": i18n.G("Show more information"),
		}), changeIDMixinArgDesc)
}

type Timing struct {
	Level    int           `json:"level,omitempty"`
	Label    string        `json:"label,omitempty"`
	Summary  string        `json:"summary,omitempty"`
	Duration time.Duration `json:"duration,omitempty"`
}

func formatDuration(dur time.Duration) string {
	return fmt.Sprintf("%dms", dur/time.Millisecond)
}

func printTiming(w io.Writer, t *Timing, verbose, doing bool) {
	var doingTimeStr, undoingTimeStr string
	if doing {
		doingTimeStr = formatDuration(t.Duration)
		undoingTimeStr = "-"
	} else {
		if doing {
			doingTimeStr = "-"
			undoingTimeStr = formatDuration(t.Duration)
		}
	}
	if verbose {
		fmt.Fprintf(w, "%s\t \t%11s\t%11s\t%s\t%s\n", strings.Repeat(" ", t.Level+1)+"^", doingTimeStr, undoingTimeStr, t.Label, strings.Repeat(" ", 2*(t.Level+1))+t.Summary)
	} else {
		fmt.Fprintf(w, "%s\t \t%11s\t%11s\t%s\n", strings.Repeat(" ", t.Level+1)+"^", doingTimeStr, undoingTimeStr, strings.Repeat(" ", 2*(t.Level+1))+t.Summary)
	}
}

type timingsData struct {
	ChangeID      string   `json:"change-id"`
	EnsureTimings []Timing `json:"ensure-timings,omitempty"`
	ChangeTimings map[string]struct {
		DoingTime      time.Duration `json:"doing-time,omitempty"`
		UndoingTime    time.Duration `json:"undoing-time,omitempty"`
		DoingTimings   []Timing      `json:"doing-timings,omitempty"`
		UndoingTimings []Timing      `json:"undoing-timings,omitempty"`
	} `json:"change-timings,omitempty"`
}

func (x *cmdChangeTimings) Execute(args []string) error {
	if len(args) > 0 {
		return ErrExtraArgs
	}

	if x.EnsureTag != "" && x.Positional.ID != "" {
		return fmt.Errorf("cannot use 'ensure' and change id together")
	}
	if x.All && x.Positional.ID != "" {
		return fmt.Errorf("cannot use 'all' and change id together")
	}

	var chgid string
	var err error
	if x.Positional.ID != "" {
		chgid, err = x.GetChangeID()
		if err != nil {
			return err
		}
	}

	// gather debug timings first
	var timings []*timingsData
	var allEnsures string
	if x.All {
		allEnsures = "true"
	} else {
		allEnsures = "false"
	}
	if err := x.client.DebugGet("change-timings", &timings, map[string]string{"change-id": chgid, "ensure": x.EnsureTag, "all": allEnsures}); err != nil {
		return err
	}

	w := tabWriter()
	if x.Verbose {
		fmt.Fprintf(w, "ID\tStatus\t%11s\t%11s\tLabel\tSummary\n", "Doing", "Undoing")
	} else {
		fmt.Fprintf(w, "ID\tStatus\t%11s\t%11s\tSummary\n", "Doing", "Undoing")
	}

	// If a specific change was requested, we expect exactly one timingsData element.
	// If "ensure" activity was requested, we may get multiple elements (for multiple executions of the ensure)
	for _, td := range timings {
		chgid = td.ChangeID

		// now combine with the other data about the change
		var chg *client.Change

		// change is optional for ensure timings
		if chgid != "" {
			chg, err = x.client.Change(chgid)
			if err != nil {
				return err
			}
		}

		if len(td.EnsureTimings) > 0 {
			for _, t := range td.EnsureTimings {
				if x.Verbose {
					fmt.Fprintf(w, "%s\t%s\t%11s\t%11s\t%s\t%s\n", "ensure", "-", formatDuration(t.Duration), "-", t.Label, t.Summary)
				} else {
					fmt.Fprintf(w, "%s\t%s\t%11s\t%11s\t%s\n", "ensure", "-", formatDuration(t.Duration), "-", t.Summary)
				}
			}
		}

		if chg != nil {
			for _, t := range chg.Tasks {
				doingTime := formatDuration(td.ChangeTimings[t.ID].DoingTime)
				if td.ChangeTimings[t.ID].DoingTime == 0 {
					doingTime = "-"
				}
				undoingTime := formatDuration(td.ChangeTimings[t.ID].UndoingTime)
				if td.ChangeTimings[t.ID].UndoingTime == 0 {
					undoingTime = "-"
				}
				summary := t.Summary
				// Duration formats to 17m14.342s or 2.038s or 970ms, so with
				// 11 chars we can go up to 59m59.999s
				if x.Verbose {
					fmt.Fprintf(w, "%s\t%s\t%11s\t%11s\t%s\t%s\n", t.ID, t.Status, doingTime, undoingTime, t.Kind, summary)
				} else {
					fmt.Fprintf(w, "%s\t%s\t%11s\t%11s\t%s\n", t.ID, t.Status, doingTime, undoingTime, summary)
				}

				for _, nested := range td.ChangeTimings[t.ID].DoingTimings {
					showDoing := true
					printTiming(w, &nested, x.Verbose, showDoing)
				}
				for _, nested := range td.ChangeTimings[t.ID].UndoingTimings {
					showDoing := false
					printTiming(w, &nested, x.Verbose, showDoing)
				}
			}
		}

		w.Flush()
		fmt.Fprintln(Stdout)
	}

	return nil
}
