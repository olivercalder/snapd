// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2017 Canonical Ltd
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

package corecfg

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/snapcore/snapd/dirs"
)

var proxyConfigKeys = map[string]bool{
	"http":  true,
	"https": true,
	"ftp":   true,
}

func etcEnvironment() string {
	return filepath.Join(dirs.GlobalRootDir, "/etc/environment")
}

func updateEtcEnvironmentConfig(path string, config map[string]string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil
	}
	defer f.Close()

	toWrite, err := updateKeyValueStream(f, proxyConfigKeys, config)
	if err != nil {
		return err
	}
	if toWrite != nil {
		return ioutil.WriteFile(path, []byte(strings.Join(toWrite, "\n")), 0644)
	}

	return nil
}

func handleProxyConfiguration() error {
	config := map[string]string{}
	for _, key := range []string{"http", "https", "ftp"} {
		output, err := snapctlGet(fmt.Sprintf("proxy.%s", key))
		if err != nil {
			return err
		}
		config[key+"_proxy"] = output
	}
	if err := updateEtcEnvironmentConfig(etcEnvironment(), config); err != nil {
		return err
	}

	return nil
}
