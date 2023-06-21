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
	"github.com/snapcore/snapd/strutil"
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

func (pd *PromptsDB) decisionIdDeepCopy(id string) (*StoredDecision, error) {
	oldDecision, exists := pd.ById[id]
	if !exists {
		return nil, ErrNoSavedDecision
	}
	newDecision := StoredDecision{
		Id:           oldDecision.Id,
		Timestamp:    oldDecision.Timestamp,
		User:         oldDecision.User,
		Snap:         oldDecision.Snap,
		App:          oldDecision.App,
		Path:         oldDecision.Path,
		ResourceType: oldDecision.ResourceType,
		Allow:        oldDecision.Allow,
		Duration:     oldDecision.Duration,
		Permissions:  make([]string, len(oldDecision.Permissions)),
		AllowType:    oldDecision.AllowType,
	}
	copy(newDecision.Permissions, oldDecision.Permissions)
	return &newDecision, nil
}

// Removes the given permission from the decision stored in ById with the
// given ID.  If the given permission is the final permission for the
// decision with the given ID, then remove the decision from ById.
func (pd *PromptsDB) decisionIdRemovePermission(id string, permission string, timestamp string) (bool, error) {
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
	decision.Timestamp = timestamp
	if len(decision.Permissions) > 0 {
		return false, nil
	}
	// Final permission deleted from decision, so remove the decision
	delete(pd.ById, id)
	return true, nil
}

func (pd *PromptsDB) decisionIdAddPermission(id string, permission string, timestamp string) error {
	decision, exists := pd.ById[id]
	if !exists {
		return ErrNoSavedDecision
	}
	index := indexOfStringInSlice(permission, decision.Permissions)
	if index != -1 {
		return ErrDecisionPermissionAlreadyExists
	}
	decision.Permissions = append(decision.Permissions, permission)
	decision.Timestamp = timestamp
	return nil
}

// TODO: unexport
func (pd *PromptsDB) FindPathInPermissionDB(db *permissionDB, path string) (string, error) {
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
	id, err := pd.FindPathInPermissionDB(permissionEntries, path)
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

// Gets the corresponding decision ID for the given path if it exists in the
// given allowMap.  If so, removes it from the map, creates a deep copy of
// the original state of the corresponding decision, and then removes the
// given permission from the decision with that ID stored in the DB.  Stores
// the deep copy of the original decision state in the given modifiedDeleted
// map and returns it, along with any error which occurred.
func (pd *PromptsDB) removePathFromMapIfExists(path string, allowMap map[string]string, permission string, modifiedDeleted map[string]*StoredDecision, timestamp string) (map[string]*StoredDecision, error) {
	if id, exists := allowMap[path]; exists {
		delete(allowMap, path)
		initialDecisionState, err := pd.decisionIdDeepCopy(id)
		if err != nil {
			return modifiedDeleted, err
		}
		_, err = pd.decisionIdRemovePermission(id, permission, timestamp)
		if err != nil {
			return modifiedDeleted, err
		}
		if _, exists := modifiedDeleted[id]; !exists {
			modifiedDeleted[id] = initialDecisionState
		}
	}
	return modifiedDeleted, nil
}

// Insert a new decision into the given permissionEntries and remove all
// previous decisions which are are more specific than the new decision.
// Returns a bool for whether the new decision was added, a map of changed
// decision IDs to the original state of those decisions before modification,
// and any error which occurs.
func (pd *PromptsDB) insertAndPrune(permissionEntries *permissionDB, decision *StoredDecision, permission string, timestamp string) (bool, map[string]*StoredDecision, error) {
	added := false
	modifiedDeleted := make(map[string]*StoredDecision)
	var err error

	newId := decision.Id
	path := decision.Path
	allow := decision.Allow
	which := decision.AllowType

	for _, allowMap := range []map[string]string{permissionEntries.Allow, permissionEntries.AllowWithDir, permissionEntries.AllowWithSubdirs} {
		modifiedDeleted, err = pd.removePathFromMapIfExists(path, allowMap, permission, modifiedDeleted, timestamp)
		if err != nil {
			return added, modifiedDeleted, err
		}
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
		for p := range toDeleteAllow {
			modifiedDeleted, err = pd.removePathFromMapIfExists(p, permissionEntries.Allow, permission, modifiedDeleted, timestamp)
		}
		if !skipNewDecision {
			permissionEntries.AllowWithDir[path] = newId
		}
	case AllowWithSubdirs:
		// delete direct match from other maps -- done above
		// delete descendants from all other maps
		toDeleteAllow := FindDescendantsInMap(path, permissionEntries.Allow)
		for p := range toDeleteAllow {
			modifiedDeleted, err = pd.removePathFromMapIfExists(p, permissionEntries.Allow, permission, modifiedDeleted, timestamp)
			if err != nil {
				return added, modifiedDeleted, err
			}
		}
		toDeleteAllowWithDir := FindDescendantsInMap(path, permissionEntries.AllowWithDir)
		for p := range toDeleteAllowWithDir {
			modifiedDeleted, err = pd.removePathFromMapIfExists(p, permissionEntries.AllowWithDir, permission, modifiedDeleted, timestamp)
			if err != nil {
				return added, modifiedDeleted, err
			}
		}
		toDeleteAllowWithSubdirs := FindDescendantsInMap(path, permissionEntries.AllowWithSubdirs)
		for p := range toDeleteAllowWithSubdirs {
			modifiedDeleted, err = pd.removePathFromMapIfExists(p, permissionEntries.AllowWithSubdirs, permission, modifiedDeleted, timestamp)
			if err != nil {
				return added, modifiedDeleted, err
			}
		}
		if !skipNewDecision {
			permissionEntries.AllowWithSubdirs[path] = newId
		}
	default:
		err = ErrUnknownAllowType
	}
	if err == nil {
		added = true
		err = pd.decisionIdAddPermission(newId, permission, timestamp)
	}
	return added, modifiedDeleted, err
}

func addDecisionPermissionToPermissionsMap(decision *StoredDecision, permission string, permissionsMap map[string]*permissionDB) error {
	id := decision.Id
	path := decision.Path
	which := decision.AllowType
	db, exists := permissionsMap[permission]
	if !exists {
		db = &permissionDB{
			Allow:            make(map[string]string),
			AllowWithDir:     make(map[string]string),
			AllowWithSubdirs: make(map[string]string),
		}
		permissionsMap[permission] = db
	}
	switch which {
	case Allow:
		db.Allow[path] = id
	case AllowWithDir:
		db.AllowWithDir[path] = id
	case AllowWithSubdirs:
		db.AllowWithSubdirs[path] = id
	default:
		return ErrUnknownAllowType
	}
	return nil
}

func addDecisionToPermissionsMap(decision *StoredDecision, permissionsMap map[string]*permissionDB) error {
	permissions := decision.Permissions
	for _, permission := range permissions {
		if err := addDecisionPermissionToPermissionsMap(decision, permission, permissionsMap); err != nil {
			return err
		}
	}
	return nil
}

func removeDecisionFromPermissionsMap(decision *StoredDecision, permissionsMap map[string]*permissionDB) error {
	path := decision.Path
	which := decision.AllowType
	origPermissions := decision.Permissions
	for _, permission := range origPermissions {
		db, exists := permissionsMap[permission]
		if !exists {
			continue
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

func (pd *PromptsDB) restoreModifiedDeleted(modifiedDeleted map[string]*StoredDecision) error {
	// compute which permissions changed
	// either call addDecisionToPermissionsMap and it will overwrite (unchanged) the existing permissions
	// or compute a diff of permissions, make sure none were added, then only re-insert permissions which were removed
	// or call removeDecisionFromPermissionsMap() followed by addDecisionToPermissionsMap()

	for id, origDecision := range modifiedDeleted {
		user := origDecision.User
		snap := origDecision.Snap
		app := origDecision.App
		permissionsMap := pd.PermissionsMapForUidAndSnapAndApp(user, snap, app)
		modifiedDecision, exists := pd.ById[id]
		if !exists {
			if err := addDecisionToPermissionsMap(origDecision, permissionsMap); err != nil {
				return err
			}
			continue
		}
		for _, permission := range origDecision.Permissions {
			if strutil.ListContains(modifiedDecision.Permissions, permission) {
				continue
			}
			if err := addDecisionPermissionToPermissionsMap(origDecision, permission, permissionsMap); err != nil {
				return err
			}
		}
		pd.ById[id] = origDecision
	}
	return nil
}

func (pd *PromptsDB) extractModifiedDeleted(modifiedDeleted map[string]*StoredDecision) ([]*StoredDecision, []*StoredDecision) {
	var modified []*StoredDecision
	var deleted []*StoredDecision
	for id, origStoredDecision := range modifiedDeleted {
		if _, exists := pd.ById[id]; exists {
			modified = append(modified, origStoredDecision)
		} else {
			deleted = append(deleted, origStoredDecision)
		}
	}
	return modified, deleted
}

// TODO: extras is ways too loosly typed right now
func (pd *PromptsDB) Set(req *notifier.Request, allow bool, extras map[ExtrasKey]string) (*StoredDecision, []*StoredDecision, []*StoredDecision, error) {
	// Returns:
	// *StoredDecision: newly-stored decision (nil if no decision stored)
	// []*StoredDecision: original state of of modified decisions
	// []*StoredDecision: original state of of deleted decisions
	// error: error which occurred

	modifiedDeleted := make(map[string]*StoredDecision)

	// nothing to store in the db
	if extras[ExtrasAlwaysPrompt] == "yes" {
		return nil, make([]*StoredDecision, 0), make([]*StoredDecision, 0), nil
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
	timestamp := newDecision.Timestamp

	permissions := WhichPermissions(req, allow, extras)

	noChange := true

	for _, permission := range permissions {
		permissionEntries := pd.MapsForUidAndSnapAndAppAndPermission(req.SubjectUid, req.Snap, req.App, permission)

		skipNewDecision, err := pd.newDecisionImpliedByPreviousDecision(permissionEntries, which, path, allow)
		if err != nil {
			// clean up this decision from permissions map, where it was partially added
			permissionsMap := pd.PermissionsMapForUidAndSnapAndApp(req.SubjectUid, req.Snap, req.App)
			_ = removeDecisionFromPermissionsMap(newDecision, permissionsMap) // ignore second error
			if err = pd.restoreModifiedDeleted(modifiedDeleted); err != nil {
				modified, deleted := pd.extractModifiedDeleted(modifiedDeleted)
				return nil, modified, deleted, err
			}
			return nil, make([]string, 0), make([]string, 0), err
		}
		if skipNewDecision {
			continue
		}

		noChange = false

		actuallyAdded, permModifiedDeleted, err := pd.insertAndPrune(permissionEntries, newDecision, permission, timestamp)
		if err != nil {
			// clean up this decision from permissions map, where it was partially added
			permissionsMap := pd.PermissionsMapForUidAndSnapAndApp(req.SubjectUid, req.Snap, req.App)
			_ = removeDecisionFromPermissionsMap(newDecision, permissionsMap) // ignore second error
			if err = pd.restoreModifiedDeleted(modifiedDeleted); err != nil {
				modified, deleted := pd.extractModifiedDeleted(modifiedDeleted)
				return nil, modified, deleted, err
			}
			return nil, make([]string, 0), make([]string, 0), err
		}

		if actuallyAdded {
			newDecision.Permissions = append(newDecision.Permissions, permission)
		}

		for oldId, origStoredDecision := range permModifiedDeleted {
			if _, exists := modifiedDeleted[oldId]; !exists {
				modifiedDeleted[oldId] = origStoredDecision
			}
		}
	}

	modified, deleted := pd.extractModifiedDeleted(modifiedDeleted)

	if noChange {
		return nil, modified, deleted, nil
	}

	pd.ById[id] = newDecision

	return newDecision, modified, deleted, pd.save()
}

func (pd *PromptsDB) Get(req *notifier.Request) (bool, error) {
	allAllow := true
	permissions := parseRequestPermissions(req)
	if len(permissions) == 0 {
		return false, ErrNoPermissions
	}
	for _, permission := range permissions {
		permissionEntries := pd.MapsForUidAndSnapAndAppAndPermission(req.SubjectUid, req.Snap, req.App, permission)
		id, err := pd.FindPathInPermissionDB(permissionEntries, req.Path)
		allAllow = allAllow && pd.decisionIdAllow(id)
		if err != nil {
			return allAllow, err
		}
	}
	logger.Noticef("found promptDB decision %v for %v (uid %v)", allAllow, req.Path, req.SubjectUid)
	return allAllow, nil
}
