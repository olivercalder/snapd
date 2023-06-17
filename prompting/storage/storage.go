package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/snapcore/snapd/dirs"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/osutil"
	"github.com/snapcore/snapd/prompting/apparmor"
	"github.com/snapcore/snapd/prompting/notifier"
)

var ErrNoPermissions = errors.New("request has no permissions set")
var ErrNoSavedDecision = errors.New("no saved prompt decision")
var ErrDecisionPermissionAlreadyExists = errors.New("permission already exists in the given prompt decision")
var ErrDecisionPermissionNotFound = errors.New("permission not found for the given prompt decision")
var ErrPermissionNotFound = errors.New("permission not found in the permission DB")
var ErrMultipleDecisions = errors.New("multiple prompt decisions for the same path and permission")
var ErrUnknownAllowType = errors.New("AllowType name does not match a known allow map")

type AllowType string

const (
	AllowUnset       AllowType = ""
	Allow            AllowType = "allow"
	AllowWithDir     AllowType = "allow-with-dir"
	AllowWithSubdirs AllowType = "allow-with-subdirs"
)

type ExtrasKey string

const (
	ExtrasAlwaysPrompt     ExtrasKey = "always-prompt"
	ExtrasAllowWithDir     ExtrasKey = "allow-directory"
	ExtrasAllowWithSubdirs ExtrasKey = "allow-subdirectories"
	ExtrasAllowExtraPerms  ExtrasKey = "allow-extra-permissions"
	ExtrasDenyWithDir      ExtrasKey = "deny-directory"
	ExtrasDenyWithSubdirs  ExtrasKey = "deny-subdirectories"
	ExtrasDenyExtraPerms   ExtrasKey = "deny-extra-permissions"
)

type DecisionDuration string

const (
	DurationOnce    DecisionDuration = "once"
	DurationSession DecisionDuration = "session"
	DurationForever DecisionDuration = "forever"
)

type StoredDecision struct {
	Id           string           `json:"id"`
	Timestamp    string           `json:"last-modified"`
	User         uint32           `json:"user"`
	Snap         string           `json:"snap-name"`
	App          string           `json:"app-name"`
	Path         string           `json:"path"`
	ResourceType string           `json:"resource-type"`
	Allow        bool             `json:"allowed"`
	Duration     DecisionDuration `json:"duration"`
	Permissions  []string         `json:"permissions"`
	AllowType    AllowType        `json:"allow-type"`
}

func newStoredDecision(req *notifier.Request, path string, allow bool, which AllowType) *StoredDecision {
	timestamp := fmt.Sprintf("%d", time.Now().UnixNano())
	newDecision := StoredDecision{
		Id:           timestamp,
		Timestamp:    timestamp,
		User:         req.SubjectUid,
		Snap:         req.Snap,
		App:          req.App,
		Path:         path,
		ResourceType: req.ResourceType,
		Allow:        allow,
		Duration:     DurationForever, // TODO: change this once duration included in request
		Permissions:  make([]string, 0),
		AllowType:    which,
	}
	return &newDecision
}

type permissionDB struct {
	// must match the AllowType definitions above
	Allow            map[string]string `json:"allow"`
	AllowWithDir     map[string]string `json:"allow-with-dir"`
	AllowWithSubdirs map[string]string `json:"allow-with-subdirs"`
}

type appDB struct {
	PerPermissionDB map[string]*permissionDB `json:"per-permission-db"`
}

type snapDB struct {
	PerApp map[string]*appDB `json:"per-app"`
}

type userDB struct {
	PerSnap map[string]*snapDB `json:"per-snap"`
}

// TODO: make this an interface
type PromptsDB struct {
	PerUser map[uint32]*userDB         `json:"per-user"`
	ById    map[string]*StoredDecision `json:"by-id"`
}

// TODO: take a dir as argument to store prompt decisions
func New() *PromptsDB {
	pd := &PromptsDB{
		PerUser: make(map[uint32]*userDB),
		ById:    make(map[string]*StoredDecision),
	}
	// TODO: error handling
	pd.load()
	return pd
}

// Returns true if decision with ID exists and has Allow value of true
func (pd *PromptsDB) decisionIdAllow(id string) bool {
	decision, exists := pd.ById[id]
	if !exists {
		return false
	}
	return decision.Allow
}

func indexOfStringInSlice(str string, slice []string) int {
	for i, item := range slice {
		if item == str {
			return i
		}
	}
	return -1
}

// Removes the given permission from the decision stored in ById with the
// given ID.
func (pd *PromptsDB) decisionIdRemovePermission(id string, permission string) (bool, error) {
	// Returns:
	// bool: removed the final permission, so the decision was deleted
	// error: nil | ErrNoSavedDecision | ErrDecisionPermissionNotFound
	decision, exists := pd.ById[id]
	if !exists {
		return false, ErrNoSavedDecision
	}
	index := indexOfStringInSlice(permission, decision.Permissions)
	if index == -1 {
		return false, ErrDecisionPermissionNotFound
	}
	decision.Permissions = append(decision.Permissions[:index], decision.Permissions[index+1:]...)
	if len(decision.Permissions) > 0 {
		return false, nil
	}
	// Final permission deleted from decision, so remove the decision
	delete(pd.ById, id)
	return true, nil
}

func (pd *PromptsDB) decisionIdAddPermission(id string, permission string) error {
	decision, exists := pd.ById[id]
	if !exists {
		return ErrNoSavedDecision
	}
	index := indexOfStringInSlice(permission, decision.Permissions)
	if index != -1 {
		return ErrDecisionPermissionAlreadyExists
	}
	decision.Permissions = append(decision.Permissions, permission)
	return nil
}

func (pd *PromptsDB) findPathInPermissionDB(db *permissionDB, path string) (string, error) {
	// Returns:
	// string: id
	// error: (nil | ErrMultipleDecisions | ErrNoSavedDecision)
	path = filepath.Clean(path)
	matchingId := ""
	var err error
	// Check if original path has exact match in db.Allow
	if id, exists := db.Allow[path]; exists {
		matchingId = id
	}
outside:
	for i := 0; i < 2; i++ {
		// Check if original path and parent of path has match in db.AllowWithDir
		// Thus, run twice
		if id, exists := db.AllowWithDir[path]; exists {
			if matchingId != "" {
				err = ErrMultipleDecisions
				matchingId = matchingId + "," + id
			} else {
				matchingId = id
			}
		}
		for {
			// Check if any ancestor of path has match in db.AllowWithSubdirs
			// Thus, loop until path is "/" or "."
			if id, exists := db.AllowWithSubdirs[path]; exists {
				if matchingId != "" {
					err = ErrMultipleDecisions
					matchingId = matchingId + "," + id
				} else {
					matchingId = id
				}
			}
			if matchingId != "" {
				return matchingId, err
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
	return matchingId, ErrNoSavedDecision
}

// TODO: unexport, possibly reintegrate into MapsForUidAndSnapAndAppAndPermission
func (pd *PromptsDB) PermissionsMapForUidAndSnapAndApp(uid uint32, snap string, app string) map[string]*permissionDB {
	userEntries := pd.PerUser[uid]
	if userEntries == nil {
		userEntries = &userDB{
			PerSnap: make(map[string]*snapDB),
		}
		pd.PerUser[uid] = userEntries
	}
	snapEntries := userEntries.PerSnap[snap]
	if snapEntries == nil {
		snapEntries = &snapDB{
			PerApp: make(map[string]*appDB),
		}
		userEntries.PerSnap[snap] = snapEntries
	}
	appEntries := snapEntries.PerApp[app]
	if appEntries == nil {
		appEntries = &appDB{
			PerPermissionDB: make(map[string]*permissionDB),
		}
		snapEntries.PerApp[app] = appEntries
	}
	return appEntries.PerPermissionDB
}

// TODO: unexport
func (pd *PromptsDB) MapsForUidAndSnapAndAppAndPermission(uid uint32, snap string, app string, permission string) *permissionDB {
	permissionsMap := pd.PermissionsMapForUidAndSnapAndApp(uid, snap, app)
	permissionEntries := permissionsMap[permission]
	if permissionEntries == nil {
		permissionEntries = &permissionDB{
			Allow:            make(map[string]string),
			AllowWithDir:     make(map[string]string),
			AllowWithSubdirs: make(map[string]string),
		}
		permissionsMap[permission] = permissionEntries
	}
	return permissionEntries
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

func whichMap(allow bool, extras map[ExtrasKey]string) AllowType {
	if (allow && extras[ExtrasAllowWithSubdirs] == "yes") || (!allow && extras[ExtrasDenyWithSubdirs] == "yes") {
		return AllowWithSubdirs
	}
	if (allow && extras[ExtrasAllowWithDir] == "yes") || (!allow && extras[ExtrasDenyWithDir] == "yes") {
		return AllowWithDir
	}
	return Allow
}

func parseRequestPermissions(req *notifier.Request) []string {
	return strings.Split(req.Permission.(apparmor.FilePermission).String(), "|")
}

func appendUnique(list []string, other []string) []string {
	combinedList := append(list, other...)
	uniqueList := make([]string, 0, len(combinedList))
	set := make(map[string]bool)
	for _, item := range combinedList {
		if _, exists := set[item]; !exists {
			set[item] = true
			uniqueList = append(uniqueList, item)
		}
	}
	return uniqueList
}

func WhichPermissions(req *notifier.Request, allow bool, extras map[ExtrasKey]string) []string {
	perms := parseRequestPermissions(req)
	if extraAllowPerms := extras[ExtrasAllowExtraPerms]; allow && extraAllowPerms != "" {
		perms = appendUnique(perms, strings.Split(extraAllowPerms, ","))
	} else if extraDenyPerms := extras[ExtrasDenyExtraPerms]; !allow && extraDenyPerms != "" {
		perms = appendUnique(perms, strings.Split(extraDenyPerms, ","))
	}
	return perms
}

// Checks whether the new rule corresponding to the decision map given by
// which, the given path, and the decision given by allow, is already implied
// by previous rules in the decision maps given by permissionEntries
func (pd *PromptsDB) newDecisionImpliedByPreviousDecision(permissionEntries *permissionDB, which AllowType, path string, allow bool) (bool, error) {
	id, err := pd.findPathInPermissionDB(permissionEntries, path)
	if err != nil {
		if err == ErrNoSavedDecision {
			return false, nil
		} else {
			return false, err
		}
	}
	alreadyAllowed := pd.decisionIdAllow(id)
	matchingMap := pd.ById[id].AllowType
	matchingPath := pd.ById[id].Path

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

	// in summary:
	// do nothing if decision matches and _not_ one of:
	//  1. new AllowWithDir, old Allow
	//  2. new AllowWithDir, old AllowWithDir, parent match
	//  3. new AllowWithSubdirs, old _not_ AllowWithSubdirs

	if alreadyAllowed == allow {
		// already in db and decision matches
		if !((which == AllowWithDir && (matchingMap == Allow || (matchingMap == AllowWithDir && matchingPath != path))) || (which == AllowWithSubdirs && matchingMap != AllowWithSubdirs)) {
			// don't need to do anything
			return true, nil
		}
	}
	return false, nil
}

// Returns a map of entries in allowMap which are children of the path, along
// with the corresponding stored decision ID
// TODO: unexport
func FindChildrenInMap(path string, allowMap map[string]string) map[string]string {
	matches := make(map[string]string)
	for p, id := range allowMap {
		if filepath.Dir(p) == path {
			matches[p] = id
		}
	}
	return matches
}

// Returns a map of entries in allowMap which are descendants of the path, along
// with the corresponding stored decision ID
// TODO: unexport
func FindDescendantsInMap(path string, allowMap map[string]string) map[string]string {
	matches := make(map[string]string)
	for pathEntry, id := range allowMap {
		if pathEntry == path {
			continue // do not include exact matches, only descendants
		}
		p := pathEntry
		for len(p) > len(path) {
			p = filepath.Dir(p)
		}
		if p == path {
			matches[pathEntry] = id
		}
	}
	return matches
}

// Insert a new decision into the given permissionEntries and remove all
// previous decisions which are are more specific than the new decision.
// Returns a bool for whether the new decision was added, a list of modified
// decisions, a list of deleted decisions, and any error which occurs.
func (pd *PromptsDB) insertAndPrune(permissionEntries *permissionDB, decision *StoredDecision, permission string) (bool, map[string]bool, error) {
	added := false
	modifiedDeleted := make(map[string]bool) // store false if modified, true if deleted
	newId := decision.Id
	path := decision.Path
	allow := decision.Allow
	which := decision.AllowType
	if oldId, exists := permissionEntries.Allow[path]; exists {
		delete(permissionEntries.Allow, path)
		deletedLastPerm, err := pd.decisionIdRemovePermission(oldId, permission)
		if err != nil {
			return added, modifiedDeleted, err
		}
		modifiedDeleted[oldId] = deletedLastPerm || modifiedDeleted[oldId]
	}
	if oldId, exists := permissionEntries.AllowWithDir[path]; exists {
		delete(permissionEntries.AllowWithDir, path)
		deletedLastPerm, err := pd.decisionIdRemovePermission(oldId, permission)
		if err != nil {
			return added, modifiedDeleted, err
		}
		modifiedDeleted[oldId] = deletedLastPerm || modifiedDeleted[oldId]
	}
	if oldId, exists := permissionEntries.AllowWithSubdirs[path]; exists {
		delete(permissionEntries.AllowWithSubdirs, path)
		deletedLastPerm, err := pd.decisionIdRemovePermission(oldId, permission)
		if err != nil {
			return added, modifiedDeleted, err
		}
		modifiedDeleted[oldId] = deletedLastPerm || modifiedDeleted[oldId]
	}

	// check if new decision is now implied by an existing one (since removing
	// exact matches), and only insert new decision if necessary
	skipNewDecision, err := pd.newDecisionImpliedByPreviousDecision(permissionEntries, which, path, allow)
	if err != nil {
		return added, modifiedDeleted, err
	}

	switch which {
	case Allow:
		// only delete direct match from other maps -- done above
		if !skipNewDecision {
			permissionEntries.Allow[path] = newId
		}
	case AllowWithDir:
		// delete direct match from other maps -- done above
		// delete direct children from Allow map
		toDeleteAllow := FindChildrenInMap(path, permissionEntries.Allow)
		for p, oldId := range toDeleteAllow {
			delete(permissionEntries.Allow, p)
			deletedLastPerm, err := pd.decisionIdRemovePermission(oldId, permission)
			if err != nil {
				return added, modifiedDeleted, err
			}
			modifiedDeleted[oldId] = deletedLastPerm || modifiedDeleted[oldId]
		}
		if !skipNewDecision {
			permissionEntries.AllowWithDir[path] = newId
		}
	case AllowWithSubdirs:
		// delete direct match from other maps -- done above
		// delete descendants from all other maps
		toDeleteAllow := FindDescendantsInMap(path, permissionEntries.Allow)
		for p, oldId := range toDeleteAllow {
			delete(permissionEntries.Allow, p)
			deletedLastPerm, err := pd.decisionIdRemovePermission(oldId, permission)
			if err != nil {
				return added, modifiedDeleted, err
			}
			modifiedDeleted[oldId] = deletedLastPerm || modifiedDeleted[oldId]
		}
		toDeleteAllowWithDir := FindDescendantsInMap(path, permissionEntries.AllowWithDir)
		for p, oldId := range toDeleteAllowWithDir {
			delete(permissionEntries.AllowWithDir, p)
			deletedLastPerm, err := pd.decisionIdRemovePermission(oldId, permission)
			if err != nil {
				return added, modifiedDeleted, err
			}
			modifiedDeleted[oldId] = deletedLastPerm || modifiedDeleted[oldId]
		}
		toDeleteAllowWithSubdirs := FindDescendantsInMap(path, permissionEntries.AllowWithSubdirs)
		for p, oldId := range toDeleteAllowWithSubdirs {
			delete(permissionEntries.AllowWithSubdirs, p)
			deletedLastPerm, err := pd.decisionIdRemovePermission(oldId, permission)
			if err != nil {
				return added, modifiedDeleted, err
			}
			modifiedDeleted[oldId] = deletedLastPerm || modifiedDeleted[oldId]
		}
		if !skipNewDecision {
			permissionEntries.AllowWithSubdirs[path] = newId
		}
	default:
		err = ErrUnknownAllowType
	}
	if err == nil {
		added = true
		err = pd.decisionIdAddPermission(newId, permission)
	}
	return added, modifiedDeleted, err
}

func removeDecisionFromPermissionsMap(decision *StoredDecision, permissionsMap map[string]*permissionDB) error {
	path := decision.Path
	which := decision.AllowType
	origPermissions := decision.Permissions
	for _, permission := range origPermissions {
		db, exists := permissionsMap[permission]
		if !exists {
			return ErrPermissionNotFound
		}
		switch which {
		case Allow:
			delete(db.Allow, path)
		case AllowWithDir:
			delete(db.AllowWithDir, path)
		case AllowWithSubdirs:
			delete(db.AllowWithSubdirs, path)
		default:
			return ErrUnknownAllowType
		}
		decision.Permissions = decision.Permissions[1:]
	}
	return nil
}

func extractModifiedDeleted(modifiedDeleted map[string]bool) ([]string, []string) {
	var modified []string
	var deleted []string
	for id, wasDeleted := range modifiedDeleted {
		if wasDeleted {
			deleted = append(deleted, id)
		} else {
			modified = append(modified, id)
		}
	}
	return modified, deleted
}

// TODO: extras is ways too loosly typed right now
func (pd *PromptsDB) Set(req *notifier.Request, allow bool, extras map[ExtrasKey]string) (string, []string, []string, error) {
	// Returns:
	// string: ID of newly-stored decision ("" if no decision stored)
	// []string: IDs of modified decisions
	// []string: IDs of deleted decisions
	// error: error which occurred

	modifiedDeleted := make(map[string]bool)

	// nothing to store in the db
	if extras[ExtrasAlwaysPrompt] == "yes" {
		return "", make([]string, 0), make([]string, 0), nil
	}
	// what if matching entry is already in the db?
	// should it be removed since we want to "always prompt"?

	which := whichMap(allow, extras)
	path := req.Path

	if strings.HasSuffix(path, "/") || ((which == AllowWithDir || which == AllowWithSubdirs) && !osutil.IsDirectory(path)) {
		path = filepath.Dir(path)
	}
	path = filepath.Clean(path)

	newDecision := newStoredDecision(req, path, allow, which)
	id := newDecision.Id

	permissions := WhichPermissions(req, allow, extras)

	noChange := true

	for _, permission := range permissions {
		permissionEntries := pd.MapsForUidAndSnapAndAppAndPermission(req.SubjectUid, req.Snap, req.App, permission)

		skipNewDecision, err := pd.newDecisionImpliedByPreviousDecision(permissionEntries, which, path, allow)
		if err != nil {
			modified, deleted := extractModifiedDeleted(modifiedDeleted)
			return "", modified, deleted, err
		}
		if skipNewDecision {
			continue
		}

		noChange = false

		actuallyAdded, permModifiedDeleted, err := pd.insertAndPrune(permissionEntries, newDecision, permission)

		if err != nil {
			permissionsMap := pd.PermissionsMapForUidAndSnapAndApp(req.SubjectUid, req.Snap, req.App)
			_ = removeDecisionFromPermissionsMap(newDecision, permissionsMap) // ignore second error
			modified, deleted := extractModifiedDeleted(modifiedDeleted)
			return "", modified, deleted, err
		}

		if actuallyAdded {
			newDecision.Permissions = append(newDecision.Permissions, permission)
		}

		for oldId, wasDeleted := range permModifiedDeleted {
			modifiedDeleted[oldId] = wasDeleted || modifiedDeleted[oldId]
		}
	}

	modified, deleted := extractModifiedDeleted(modifiedDeleted)

	if noChange {
		return "", modified, deleted, nil
	}

	pd.ById[id] = newDecision

	return id, modified, deleted, pd.save()
}

func (pd *PromptsDB) Get(req *notifier.Request) (bool, error) {
	allAllow := true
	permissions := parseRequestPermissions(req)
	if len(permissions) == 0 {
		return false, ErrNoPermissions
	}
	for _, permission := range permissions {
		permissionEntries := pd.MapsForUidAndSnapAndAppAndPermission(req.SubjectUid, req.Snap, req.App, permission)
		id, err := pd.findPathInPermissionDB(permissionEntries, req.Path)
		allAllow = allAllow && pd.decisionIdAllow(id)
		if err != nil {
			return allAllow, err
		}
	}
	logger.Noticef("found promptDB decision %v for %v (uid %v)", allAllow, req.Path, req.SubjectUid)
	return allAllow, nil
}
