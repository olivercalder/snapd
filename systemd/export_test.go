// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2016 Canonical Ltd
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

package systemd

import (
	"time"
)

var (
	SystemdRun = run // NOTE: plain Run clashes with check.v1
	Jctl       = jctl
	RestartMap = restartMap
)

func MockStopStepsStopDelay() func() {
	oldSteps := stopSteps
	oldDelay := stopDelay
	stopSteps = 2
	stopDelay = time.Millisecond
	return func() {
		stopSteps = oldSteps
		stopDelay = oldDelay
	}
}
