// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2018 Canonical Ltd
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

package backend

import (
	"archive/tar"
	"archive/zip"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/snapcore/snapd/client"
	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/snap"
	"github.com/snapcore/snapd/snapdenv"
	"github.com/snapcore/snapd/strutil"
)

const (
	archiveName  = "archive.tgz"
	metadataName = "meta.json"
	metaHashName = "meta.sha3_384"

	userArchivePrefix = "user/"
	userArchiveSuffix = ".tgz"
)

var (
	// Stop is used to ask Iter to stop iteration, without it being an error.
	Stop = errors.New("stop iteration")

	osOpen      = os.Open
	dirNames    = (*os.File).Readdirnames
	backendOpen = Open
)

// Flags encompasses extra flags for snapshots backend Save.
type Flags struct {
	Auto bool
}

// Iter loops over all snapshots in the snapshots directory, applying the given
// function to each. The snapshot will be closed after the function returns. If
// the function returns an error, iteration is stopped (and if the error isn't
// Stop, it's returned as the error of the iterator).
func Iter(ctx context.Context, f func(*Reader) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	dir, err := osOpen(dirs.SnapshotsDir)
	if err != nil {
		if osutil.IsDirNotExist(err) {
			// no dir -> no snapshots
			return nil
		}
		return fmt.Errorf("cannot open snapshots directory: %v", err)
	}
	defer dir.Close()

	var names []string
	var readErr error
	for readErr == nil && err == nil {
		names, readErr = dirNames(dir, 100)
		// note os.Readdirnames can return a non-empty names and a non-nil err
		for _, name := range names {
			if err = ctx.Err(); err != nil {
				break
			}

			filename := filepath.Join(dirs.SnapshotsDir, name)
			reader, openError := backendOpen(filename)
			// reader can be non-nil even when openError is not nil (in
			// which case reader.Broken will have a reason). f can
			// check and either ignore or return an error when
			// finding a broken snapshot.
			if reader != nil {
				err = f(reader)
			} else {
				// TODO: use warnings instead
				logger.Noticef("Cannot open snapshot %q: %v.", name, openError)
			}
			if openError == nil {
				// if openError was nil the snapshot was opened and needs closing
				if closeError := reader.Close(); err == nil {
					err = closeError
				}
			}
			if err != nil {
				break
			}
		}
	}

	if readErr != nil && readErr != io.EOF {
		return readErr
	}

	if err == Stop {
		err = nil
	}

	return err
}

// List valid snapshots sets.
func List(ctx context.Context, setID uint64, snapNames []string) ([]client.SnapshotSet, error) {
	setshots := map[uint64][]*client.Snapshot{}
	err := Iter(ctx, func(reader *Reader) error {
		if setID == 0 || reader.SetID == setID {
			if len(snapNames) == 0 || strutil.ListContains(snapNames, reader.Snap) {
				setshots[reader.SetID] = append(setshots[reader.SetID], &reader.Snapshot)
			}
		}
		return nil
	})

	sets := make([]client.SnapshotSet, 0, len(setshots))
	for id, shots := range setshots {
		sort.Sort(bySnap(shots))
		sets = append(sets, client.SnapshotSet{ID: id, Snapshots: shots})
	}

	sort.Sort(byID(sets))

	return sets, err
}

// Filename of the given client.Snapshot in this backend.
func Filename(snapshot *client.Snapshot) string {
	// this _needs_ the snap name and version to be valid
	return filepath.Join(dirs.SnapshotsDir, fmt.Sprintf("%d_%s_%s_%s.zip", snapshot.SetID, snapshot.Snap, snapshot.Version, snapshot.Revision))
}

func snapshotFromFilename(f string) (*client.Snapshot, error) {
	var setID uint64
	var revision int
	var snapName, version string
	parseF := strings.Replace(f, "_", " ", 3)
	parseF = strings.Replace(parseF, ".zip", "", 1)
	if _, err := fmt.Sscanf(parseF, "%d %s %s %d", &setID, &snapName, &version, &revision); err != nil {
		return nil, fmt.Errorf("unexpected filename format: %v", err)
	}

	snapshot := &client.Snapshot{
		SetID:    setID,
		Time:     time.Time{},
		Snap:     snapName,
		Revision: snap.Revision{N: revision},
		Version:  version,
	}
	return snapshot, nil
}

// Save a snapshot
func Save(ctx context.Context, id uint64, si *snap.Info, cfg map[string]interface{}, usernames []string, flags *Flags) (*client.Snapshot, error) {
	if err := os.MkdirAll(dirs.SnapshotsDir, 0700); err != nil {
		return nil, err
	}

	var auto bool
	if flags != nil {
		auto = flags.Auto
	}

	snapshot := &client.Snapshot{
		SetID:    id,
		Snap:     si.InstanceName(),
		SnapID:   si.SnapID,
		Revision: si.Revision,
		Version:  si.Version,
		Epoch:    si.Epoch,
		Time:     time.Now(),
		SHA3_384: make(map[string]string),
		Size:     0,
		Conf:     cfg,
		Auto:     auto,
	}

	aw, err := osutil.NewAtomicFile(Filename(snapshot), 0600, 0, osutil.NoChown, osutil.NoChown)
	if err != nil {
		return nil, err
	}
	// if things worked, we'll commit (and Cancel becomes a NOP)
	defer aw.Cancel()

	w := zip.NewWriter(aw)
	defer w.Close() // note this does not close the file descriptor (that's done by hand on the atomic writer, above)
	if err := addDirToZip(ctx, snapshot, w, "root", archiveName, si.DataDir()); err != nil {
		return nil, err
	}

	users, err := usersForUsernames(usernames)
	if err != nil {
		return nil, err
	}

	for _, usr := range users {
		if err := addDirToZip(ctx, snapshot, w, usr.Username, userArchiveName(usr), si.UserDataDir(usr.HomeDir)); err != nil {
			return nil, err
		}
	}

	metaWriter, err := w.Create(metadataName)
	if err != nil {
		return nil, err
	}

	hasher := crypto.SHA3_384.New()
	enc := json.NewEncoder(io.MultiWriter(metaWriter, hasher))
	if err := enc.Encode(snapshot); err != nil {
		return nil, err
	}

	hashWriter, err := w.Create(metaHashName)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(hashWriter, "%x\n", hasher.Sum(nil))
	if err := w.Close(); err != nil {
		return nil, err
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if err := aw.Commit(); err != nil {
		return nil, err
	}

	return snapshot, nil
}

var isTesting = snapdenv.Testing()

func addDirToZip(ctx context.Context, snapshot *client.Snapshot, w *zip.Writer, username string, entry, dir string) error {
	parent, revdir := filepath.Split(dir)
	exists, isDir, err := osutil.DirExists(parent)
	if err != nil {
		return err
	}
	if exists && !isDir {
		logger.Noticef("Not saving directories under %q in snapshot #%d of %q as it is not a directory.", parent, snapshot.SetID, snapshot.Snap)
		return nil
	}
	if !exists {
		logger.Debugf("Not saving directories under %q in snapshot #%d of %q as it is does not exist.", parent, snapshot.SetID, snapshot.Snap)
		return nil
	}
	tarArgs := []string{
		"--create",
		"--sparse", "--gzip",
		"--directory", parent,
	}

	noRev, noCommon := true, true

	exists, isDir, err = osutil.DirExists(dir)
	if err != nil {
		return err
	}
	switch {
	case exists && isDir:
		tarArgs = append(tarArgs, revdir)
		noRev = false
	case exists && !isDir:
		logger.Noticef("Not saving %q in snapshot #%d of %q as it is not a directory.", dir, snapshot.SetID, snapshot.Snap)
	case !exists:
		logger.Debugf("Not saving %q in snapshot #%d of %q as it is does not exist.", dir, snapshot.SetID, snapshot.Snap)
	}

	common := filepath.Join(parent, "common")
	exists, isDir, err = osutil.DirExists(common)
	if err != nil {
		return err
	}
	switch {
	case exists && isDir:
		tarArgs = append(tarArgs, "common")
		noCommon = false
	case exists && !isDir:
		logger.Noticef("Not saving %q in snapshot #%d of %q as it is not a directory.", common, snapshot.SetID, snapshot.Snap)
	case !exists:
		logger.Debugf("Not saving %q in snapshot #%d of %q as it is does not exist.", common, snapshot.SetID, snapshot.Snap)
	}

	if noCommon && noRev {
		return nil
	}

	archiveWriter, err := w.CreateHeader(&zip.FileHeader{Name: entry})
	if err != nil {
		return err
	}

	var sz osutil.Sizer
	hasher := crypto.SHA3_384.New()

	cmd := tarAsUser(username, tarArgs...)
	cmd.Stdout = io.MultiWriter(archiveWriter, hasher, &sz)
	matchCounter := &strutil.MatchCounter{N: 1}
	cmd.Stderr = matchCounter
	if isTesting {
		matchCounter.N = -1
		cmd.Stderr = io.MultiWriter(os.Stderr, matchCounter)
	}
	if err := osutil.RunWithContext(ctx, cmd); err != nil {
		matches, count := matchCounter.Matches()
		if count > 0 {
			return fmt.Errorf("cannot create archive: %s (and %d more)", matches[0], count-1)
		}
		return fmt.Errorf("tar failed: %v", err)
	}

	snapshot.SHA3_384[entry] = fmt.Sprintf("%x", hasher.Sum(nil))
	snapshot.Size += sz.Size()

	return nil
}

// Import a snapshot from the export file format
func Import(ctx context.Context, id uint64, r io.Reader) ([]string, error) {
	comment := fmt.Sprintf("snapshot %d", id)

	// prepare cache location to unpack the import file
	p := path.Join(dirs.SnapCacheDir, "snapshots", string(id))
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		return nil, fmt.Errorf("snapshot import already in progress for ID `%d`", id)
	}
	if err := os.MkdirAll(p, 0755); err != nil {
		return nil, fmt.Errorf("failed creating import cache: %v", err)
	}
	defer os.RemoveAll(p)

	// unpack the tar file to a temporary location (so the contents can be validated)
	exportFound, err := unpackSnapshotImport(r, p)
	if err != nil {
		return nil, err
	}

	if !exportFound {
		return nil, fmt.Errorf("snapshot import file incomplete: no export.json file")
	}

	// XXX: check the snapshot hashes (these are not in export.json at present)

	// walk the cache directory to store the files
	dir, err := osOpen(p)
	if err != nil {
		return nil, fmt.Errorf("failed opening import cache: %v", comment)
	}
	defer dir.Close()
	names, err := dirNames(dir, 100)
	if err != nil {
		return nil, fmt.Errorf("failed read from import cache: %v", comment)
	}

	// move the files into place with the new local set ID
	return moveCachedSnapshots(names, id, p)
}

func unpackSnapshotImport(r io.Reader, p string) (bool, error) {
	tr := tar.NewReader(r)
	var tarErr error
	var header *tar.Header
	var exportFound bool
	for tarErr == nil {
		var skip bool
		header, tarErr = tr.Next()
		switch {
		case tarErr == io.EOF:
			skip = true
		case tarErr != nil:
			return false, fmt.Errorf("failed reading snapshot import: %v", tarErr)
		case header == nil:
			// should not happen
			skip = true
		case header.Typeflag == tar.TypeDir:
			// should not happen, but ignore directories
			skip = true
		}

		if skip {
			continue
		}

		if header.Name == "export.json" {
			exportFound = true
		}

		target := path.Join(p, header.Name)
		t, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
		if err != nil {
			return false, fmt.Errorf("failed creating file `%s`: %v", target, err)
		}
		if _, err := io.Copy(t, tr); err != nil {
			return false, fmt.Errorf("failed copying file `%s`: %v", target, err)
		}

		t.Close()
	}
	return exportFound, nil
}

func moveCachedSnapshots(names []string, id uint64, p string) ([]string, error) {
	snaps := []string{}
	for _, name := range names {
		if name == "export.json" {
			// ignore metadata file
			continue
		}
		snapshot, err := snapshotFromFilename(name)
		if err != nil {
			return nil, err
		}
		snaps = append(snaps, snapshot.Snap)

		// set the new setID and get the new filename
		snapshot.SetID = id
		new := Filename(snapshot)
		old := path.Join(p, name)

		if err := os.Rename(old, new); err != nil {
			return nil, err
		}
	}
	return snaps, nil
}
