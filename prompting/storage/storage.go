package storage

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/prompting/notifier"
)

var ErrNoSavedDecision = errors.New("no saved prompt decision")
var ErrMultipleDecisions = errors.New("multiple prompt decisions for the same path")

const (
	// must match the specification for extra information map returned by the prompt
	extrasAlwaysPrompt     = "always-prompt"
	extrasAllowWithDir     = "allow-directory"
	extrasAllowWithSubdirs = "allow-subdirectories"
	extrasAllowExtraPerms  = "allow-extra-permissions"
	extrasDenyWithDir      = "deny-directory"
	extrasDenyWithSubdirs  = "deny-subdirectories"
	extrasDenyExtraPerms   = "deny-extra-permissions"
)

type labelDB struct {
	Allow            map[string]bool `json:"allow"`
	AllowWithDir     map[string]bool `json:"allow-with-dir"`
	AllowWithSubdirs map[string]bool `json:"allow-with-subdir"`
	// XXX: Always check with the following priority: Allow, then AllowWithDir, then AllowWithSubdirs
}

// TODO: use Permission (interface{}) in place of bool to store particular permissions

type userDB struct {
	PerLabelDB map[string]*labelDB `json:"per-label-db"`
}

// TODO: make this an interface
type PromptsDB struct {
	PerUser map[uint32]*userDB `json:"per-user"`
}

// TODO: take a dir as argument to store prompt decisions
func New() *PromptsDB {
	pd := &PromptsDB{PerUser: make(map[uint32]*userDB)}
	// TODO: error handling
	pd.load()
	return pd
}

func findPathInLabelDB(db *labelDB, path string) (bool, error, map[string]bool, string) {
	// Returns:
	// bool: allow
	// error: (nil | ErrMultipleDecisions | ErrNoSavedDecision)
	// map[string]bool: (db.Allow | db.AllowWithDir | db.AllowWithSubdirs)
	// string: matching path current in the db
	path = filepath.Clean(path)
	storedAllow := true
	var which map[string]bool = nil
	var err error
	// Check if original path has exact match in db.Allow
	if allow, exists := db.Allow[path]; exists {
		storedAllow = storedAllow && allow
		which = db.Allow
	}
outside:
	for i := 0; i < 2; i++ {
		// Check if original path and parent of path has match in db.AllowWithDir
		// Thus, run twice
		if allow, exists := db.AllowWithDir[path]; exists {
			if which != nil {
				return false, ErrMultipleDecisions, nil, path
			}
			storedAllow = storedAllow && allow
			which = db.AllowWithDir
		}
		for {
			// Check if any ancestor of path has match in db.AllowWithSubdirs
			// Thus, loop until path is "/" or "."
			if allow, exists := db.AllowWithSubdirs[path]; exists {
				if which != nil {
					return false, ErrMultipleDecisions, nil, path
				}
				storedAllow = storedAllow && allow
				which = db.AllowWithSubdirs
			}
			if which != nil {
				return storedAllow, err, which, path
			}
			path = filepath.Dir(path)
			if path == "/" || path == "." {
				break outside
			}
			// Only run once during the first loop for AllowWithDir
			if i == 0 {
				break
			}
			// Otherwise, loop until path is "/" or "."
		}
	}
	return false, ErrNoSavedDecision, nil, ""
}

// TODO: unexport
func (pd *PromptsDB) MapsForUidAndLabel(uid uint32, label string) *labelDB {
	userEntries := pd.PerUser[uid]
	if userEntries == nil {
		userEntries = &userDB{
			PerLabelDB: make(map[string]*labelDB),
		}
		pd.PerUser[uid] = userEntries
	}
	labelEntries := userEntries.PerLabelDB[label]
	if labelEntries == nil {
		labelEntries = &labelDB{
			Allow:            make(map[string]bool),
			AllowWithDir:     make(map[string]bool),
			AllowWithSubdirs: make(map[string]bool),
		}
		userEntries.PerLabelDB[label] = labelEntries
	}
	return labelEntries
}

func (pd *PromptsDB) dbpath() string {
	return filepath.Join(dirs.SnapdStateDir(dirs.GlobalRootDir), "prompt.json")
}

func (pd *PromptsDB) save() error {
	b, err := json.Marshal(pd.PerUser)
	if err != nil {
		return err
	}
	target := pd.dbpath()
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	return osutil.AtomicWriteFile(target, b, 0600, 0)
}

func (pd *PromptsDB) load() error {
	target := pd.dbpath()
	f, err := os.Open(target)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewDecoder(f).Decode(&pd.PerUser)
}

// TODO: extras is ways too loosly typed right now
func (pd *PromptsDB) Set(req *notifier.Request, allow bool, extras map[string]string) error {
	// nothing to store in the db
	if extras[extrasAlwaysPrompt] == "yes" {
		return nil
	}
	// what if matching entry is already in the db?
	// should it be removed since we want to "always prompt"?
	labelEntries := pd.MapsForUidAndLabel(req.SubjectUid, req.Label)

	path := req.Path
	if strings.HasSuffix(path, "/") || (((allow && (extras[extrasAllowWithDir] == "yes" || extras[extrasAllowWithSubdirs] == "yes")) || (!allow && (extras[extrasDenyWithDir] == "yes" || extras[extrasDenyWithSubdirs] == "yes"))) && !osutil.IsDirectory(path)) {
		path = filepath.Dir(path)
	}
	path = filepath.Clean(path)
	alreadyAllowed, err, which, matchingPath := findPathInLabelDB(labelEntries, path)
	if err != nil && err != ErrNoSavedDecision {
		return err
	}

	// if path matches entry already in a different map (XXX means can't return early):
	// new Allow, old Allow -> replace if different
	// new Allow, old AllowWithDir, exact match -> replace if different (forces prompt for entries in directory of path)
	// new Allow, old AllowWithSubdirs, exact match -> same as ^^
	// new Allow, old AllowWithDir, parent match -> insert if different
	// new Allow, old AllowWithSubdirs, ancestor match -> same as ^^
	// new AllowWithDir, old Allow -> replace always XXX
	// new AllowWithDir, old AllowWithDir, exact match -> replace if different
	// new AllowWithDir, old AllowWithSubdir, exact match -> same as ^^
	// new AllowWithDir, old AllowWithDir, parent match -> insert always XXX
	// new AllowWithDir, old AllowWithSubdir, ancestor match -> insert if different
	// new AllowWithSubdir, old Allow -> replace always XXX
	// new AllowWithSubdir, old AllowWithDir, exact match -> replace always XXX
	// new AllowWithSubdir, old AllowWithSubdir, exact match -> replace if different
	// new AllowWithSubdir, old AllowWithDir, parent match -> insert always XXX
	// new AllowWithSubdir, old AllowWithSubdir, ancestor match -> insert if different

	// in summary:
	// do nothing if decision matches and _not_ one of:
	//  1. new AllowWithDir, old Allow
	//  2. new AllowWithDir, old AllowWithDir, parent match
	//  3. new AllowWithSubdir, old _not_ AllowWithSubdir
	// otherwise:
	// remove any existing exact match (no-op if there is none)
	// insert the path with the decision in the correct map

	if (err == nil) && (alreadyAllowed == allow) {
		// already in db and decision matches
		if !((extras[extrasAllowWithDir] == "yes" && (&which == &labelEntries.Allow || (&which == &labelEntries.AllowWithDir && matchingPath != path))) || (extras[extrasAllowWithSubdirs] == "yes" && &which != &labelEntries.AllowWithSubdirs)) {
			// don't need to do anything
			return nil
		}
	}

	// if there's an exact match in one of the maps, delete it
	if matchingPath == path {
		// XXX maybe don't even need if statement here, as deletion is no-op if key not in map
		delete(which, path)
	}

	if (allow && extras[extrasAllowWithSubdirs] == "yes") || (!allow && extras[extrasDenyWithSubdirs] == "yes") {
		labelEntries.AllowWithSubdirs[path] = allow
	} else if (allow && extras[extrasAllowWithDir] == "yes") || (!allow && extras[extrasDenyWithDir] == "yes") {
		labelEntries.AllowWithDir[path] = allow
	} else {
		labelEntries.Allow[path] = allow
	}

	return pd.save()
}

func (pd *PromptsDB) Get(req *notifier.Request) (bool, error) {
	labelEntries := pd.MapsForUidAndLabel(req.SubjectUid, req.Label)
	allow, err, _, _ := findPathInLabelDB(labelEntries, req.Path)
	return allow, err
}
