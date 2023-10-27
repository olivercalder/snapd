package promptrequests

import (
	"errors"
	"reflect"
	"sync"

	"github.com/snapcore/snapd/overlord/ifacestate/apparmorprompting/common"
)

var ErrConflictingRequestId = errors.New("a prompt request with the same ID already exists")
var ErrRequestIdNotFound = errors.New("no request with the given ID found for the given user")
var ErrUserNotFound = errors.New("no prompt requests found for the given user")

type PromptRequest struct {
	Id          string                  `json:"id"`
	Timestamp   string                  `json:"timestamp"`
	Snap        string                  `json:"snap"`
	App         string                  `json:"app"`
	Path        string                  `json:"path"`
	Permissions []common.PermissionType `json:"permissions"`
	replyChans  []chan bool             `json:"-"`
}

type userRequestDB struct {
	ById map[string]*PromptRequest
}

type RequestDB struct {
	PerUser map[uint32]*userRequestDB
	mutex   sync.Mutex
}

func New() *RequestDB {
	return &RequestDB{
		PerUser: make(map[uint32]*userRequestDB),
	}
}

// Creates, adds, and returns a new prompt request from the given parameters.
//
// If the parameters exactly match an existing request, merge it with that
// existing request instead, and do not add a new request. If a new request was
// added, returns the new request and false, indicating the request was not
// merged. If it was merged with an identical existing request, returns the
// existing request and true.
func (rdb *RequestDB) AddOrMerge(user uint32, snap string, app string, path string, permissions []common.PermissionType, replyChan chan bool) (*PromptRequest, bool) {
	rdb.mutex.Lock()
	defer rdb.mutex.Unlock()
	userEntry, exists := rdb.PerUser[user]
	if !exists {
		rdb.PerUser[user] = &userRequestDB{
			ById: make(map[string]*PromptRequest),
		}
		userEntry = rdb.PerUser[user]
	}

	// Search for an identical existing request, merge if found
	for _, req := range userEntry.ById {
		if req.Snap == snap && req.App == app && req.Path == path && reflect.DeepEqual(req.Permissions, permissions) {
			req.replyChans = append(req.replyChans, replyChan)
			return req, true
		}
	}

	id, timestamp := common.NewIdAndTimestamp()
	req := &PromptRequest{
		Id:          id,
		Timestamp:   timestamp,
		Snap:        snap,
		App:         app,
		Path:        path,
		Permissions: permissions, // TODO: copy permissions list?
		replyChans:  []chan bool{replyChan},
	}
	userEntry.ById[id] = req
	return req, false
}

func (rdb *RequestDB) Requests(user uint32) []*PromptRequest {
	rdb.mutex.Lock()
	defer rdb.mutex.Unlock()
	userEntry, exists := rdb.PerUser[user]
	if !exists {
		return make([]*PromptRequest, 0)
	}
	requests := make([]*PromptRequest, 0, len(userEntry.ById))
	for _, req := range userEntry.ById {
		requests = append(requests, req)
	}
	return requests
}

func (rdb *RequestDB) RequestWithId(user uint32, id string) (*PromptRequest, error) {
	rdb.mutex.Lock()
	defer rdb.mutex.Unlock()
	userEntry, exists := rdb.PerUser[user]
	if !exists {
		return nil, ErrUserNotFound
	}
	req, exists := userEntry.ById[id]
	if !exists {
		return nil, ErrRequestIdNotFound
	}
	return req, nil
}

// Reply resolves the request with the given ID using the given outcome.
func (rdb *RequestDB) Reply(user uint32, id string, outcome common.OutcomeType) (*PromptRequest, error) {
	rdb.mutex.Lock()
	defer rdb.mutex.Unlock()
	userEntry, exists := rdb.PerUser[user]
	if !exists || len(userEntry.ById) == 0 {
		return nil, ErrUserNotFound
	}
	req, exists := userEntry.ById[id]
	if !exists {
		return nil, ErrRequestIdNotFound
	}
	var outcomeBool bool
	switch outcome {
	case common.OutcomeAllow:
		outcomeBool = true
	case common.OutcomeDeny:
		outcomeBool = false
	default:
		return nil, common.ErrInvalidOutcome
	}
	for _, replyChan := range req.replyChans {
		replyChan <- outcomeBool
	}
	delete(userEntry.ById, id)
	return req, nil
}

// If any existing requests are satisfied by the given rule, send the decision
// along their respective channels, and return their IDs.
func (rdb *RequestDB) HandleNewRule(user uint32, snap string, app string, pathPattern string, outcome common.OutcomeType, permissions []common.PermissionType) ([]string, error) {
	rdb.mutex.Lock()
	defer rdb.mutex.Unlock()
	var outcomeBool bool
	switch outcome {
	case common.OutcomeAllow:
		outcomeBool = true
	case common.OutcomeDeny:
		outcomeBool = false
	default:
		return nil, common.ErrInvalidOutcome
	}
	var satisfiedReqIds []string
	userEntry, exists := rdb.PerUser[user]
	if !exists {
		return satisfiedReqIds, nil
	}
	for id, req := range userEntry.ById {
		if !(snap == req.Snap && app == req.App) {
			continue
		}
		matched, err := common.PathPatternMatches(pathPattern, req.Path)
		if err != nil {
			// Only possible error is ErrBadPattern
			return nil, err
		}
		if !matched {
			continue
		}
		remainingPermissions := req.Permissions
		for _, perm := range permissions {
			remainingPermissions, _ = common.RemovePermissionFromList(remainingPermissions, perm)
		}
		if len(remainingPermissions) > 0 {
			// If we don't satisfy all permissions with the new rule,
			// leave it up to the UI to prompt for all at once.
			continue
		}
		// all permissions of request satisfied
		for _, replyChan := range req.replyChans {
			replyChan <- outcomeBool
		}
		delete(userEntry.ById, id)
		satisfiedReqIds = append(satisfiedReqIds, id)
	}
	return satisfiedReqIds, nil
}
