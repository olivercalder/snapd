package apparmorprompting

import (
	"fmt"
	"sync"

	"gopkg.in/tomb.v2"

	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/overlord/ifacestate/apparmorprompting/accessrules"
	"github.com/snapcore/snapd/overlord/ifacestate/apparmorprompting/common"
	"github.com/snapcore/snapd/overlord/ifacestate/apparmorprompting/promptrequests"
	"github.com/snapcore/snapd/sandbox/apparmor/notify"
	"github.com/snapcore/snapd/sandbox/apparmor/notify/listener"
)

var userOverride int = 1234

type Interface interface {
	Connect() error
	Run() error
	Stop() error
}

type followReqEntry struct {
	respWriters map[*FollowRequestsSeqResponseWriter]bool
	lock        sync.Mutex
}

type appEntry struct {
	respWriters map[*FollowRulesSeqResponseWriter]bool
}

type snapEntry struct {
	respWriters map[*FollowRulesSeqResponseWriter]bool
	appEntries  map[string]*appEntry
}

type followRuleEntry struct {
	snapEntries map[string]*snapEntry
	lock        sync.Mutex
}

type Prompting struct {
	tomb              tomb.Tomb
	listener          *listener.Listener
	requests          *promptrequests.RequestDB
	rules             *accessrules.AccessRuleDB
	followReqEntries  map[int]*followReqEntry
	followReqLock     sync.Mutex
	followRuleEntries map[int]*followRuleEntry
	followRuleLock    sync.Mutex
}

func New() Interface {
	p := &Prompting{
		followReqEntries:  make(map[int]*followReqEntry),
		followRuleEntries: make(map[int]*followRuleEntry),
	}
	return p
}

func (p *Prompting) Connect() error {
	if !notify.SupportAvailable() {
		return nil
	}
	l, err := listener.Register()
	if err != nil {
		return err
	}
	p.listener = l
	p.requests = promptrequests.New()
	p.rules, _ = accessrules.New() // ignore error (failed to load existing rules)
	return nil
}

func (p *Prompting) disconnect() error {
	if p.listener == nil {
		return nil
	}
	if err := p.listener.Close(); err != nil {
		return err
	}
	return nil
}

func (p *Prompting) followReqEntryForUser(userId int) *followReqEntry {
	p.followReqLock.Lock()
	defer p.followReqLock.Unlock()
	entry, exists := p.followReqEntries[userId]
	if !exists {
		return nil
	}
	return entry
}

func (p *Prompting) followReqEntryForUserOrInit(userId int) *followReqEntry {
	p.followReqLock.Lock()
	defer p.followReqLock.Unlock()
	entry, exists := p.followReqEntries[userId]
	if !exists {
		entry = &followReqEntry{
			respWriters: make(map[*FollowRequestsSeqResponseWriter]bool),
		}
		p.followReqEntries[userId] = entry
	}
	return entry
}

func (p *Prompting) followRuleEntryForUser(userId int) *followRuleEntry {
	p.followRuleLock.Lock()
	defer p.followRuleLock.Unlock()
	entry, exists := p.followRuleEntries[userId]
	if !exists {
		return nil
	}
	return entry
}

func (p *Prompting) followRuleEntryForUserOrInit(userId int) *followRuleEntry {
	p.followRuleLock.Lock()
	defer p.followRuleLock.Unlock()
	entry, exists := p.followRuleEntries[userId]
	if !exists {
		entry = &followRuleEntry{
			snapEntries: make(map[string]*snapEntry),
		}
		p.followRuleEntries[userId] = entry
	}
	return entry
}

func (p *Prompting) RegisterAndPopulateFollowRequestsChan(userId int, requestsCh chan *promptrequests.PromptRequest) *FollowRequestsSeqResponseWriter {
	userId = userOverride // TODO: undo this! This is just for debugging

	respWriter := newFollowRequestsSeqResponseWriter(requestsCh)

	entry := p.followReqEntryForUserOrInit(userId)

	entry.lock.Lock()
	defer entry.lock.Unlock()
	entry.respWriters[respWriter] = true

	// Start goroutine to wait until respWriter should be removed from
	// entry.respWriters, either because it has been stopped or the tomb
	// is dying.
	p.tomb.Go(func() error {
		select {
		case <-p.tomb.Dying():
			respWriter.Stop()
		case <-respWriter.Stopping():
		}
		entry.lock.Lock()
		defer entry.lock.Unlock()
		delete(entry.respWriters, respWriter)
		return nil
	})

	// Record current outstanding requests before unlocking.
	// This way, no new requests (which are sent out independently) can
	// preempt getting current requests and thus be sent here as well,
	// causing duplicate requests.
	outstandingRequests := p.requests.Requests(userId)
	p.tomb.Go(func() error {
		// This could block if the chan is filled, so separate goroutine
		for _, req := range outstandingRequests {
			if !respWriter.WriteRequest(req) {
				// respWriter has been stopped
				break
			}
		}
		return nil
	})
	return respWriter
}

func (p *Prompting) RegisterAndPopulateFollowRulesChan(userId int, snap string, app string, rulesCh chan *accessrules.AccessRule) *FollowRulesSeqResponseWriter {
	userId = userOverride // TODO: undo this! This is just for debugging

	respWriter := newFollowRulesSeqResponseWriter(rulesCh)

	entry := p.followRuleEntryForUserOrInit(userId)

	entry.lock.Lock()
	defer entry.lock.Unlock()

	var outstandingRules []*accessrules.AccessRule

	sEntry := entry.snapEntries[snap]
	if sEntry == nil {
		sEntry = &snapEntry{
			respWriters: make(map[*FollowRulesSeqResponseWriter]bool),
			appEntries:  make(map[string]*appEntry),
		}
		entry.snapEntries[snap] = sEntry
	}
	// The following is ugly, but while addresses of structs may change,
	// addresses of entries containing maps should not, so it is safe to
	// retain those entries, rather than storing their embedded maps in a
	// common variable.
	if app != "" {
		saEntry := sEntry.appEntries[app]
		if saEntry == nil {
			saEntry = &appEntry{
				respWriters: make(map[*FollowRulesSeqResponseWriter]bool),
			}
			sEntry.appEntries[app] = saEntry
		}
		saEntry.respWriters[respWriter] = true
		// Start goroutine to wait until respWriter should be removed
		// from saEntry.respWriters, either because it has been stopped
		// or the tomb is dying.
		p.tomb.Go(func() error {
			select {
			case <-p.tomb.Dying():
				respWriter.Stop()
			case <-respWriter.Stopping():
			}
			entry.lock.Lock()
			defer entry.lock.Unlock()
			delete(saEntry.respWriters, respWriter)
			return nil
		})
		outstandingRules = p.rules.RulesForSnapApp(userId, snap, app)
	} else {
		sEntry.respWriters[respWriter] = true
		// Start goroutine to wait until respWriter should be removed
		// from sEntry.respWriters, either because it has been stopped
		// or the tomb is dying.
		p.tomb.Go(func() error {
			select {
			case <-p.tomb.Dying():
				respWriter.Stop()
			case <-respWriter.Stopping():
			}
			entry.lock.Lock()
			defer entry.lock.Unlock()
			delete(sEntry.respWriters, respWriter)
			return nil
		})
		outstandingRules = p.rules.RulesForSnap(userId, snap)
	}

	p.tomb.Go(func() error {
		// This could block if the chan is filled, so separate goroutine
		for _, req := range outstandingRules {
			if !respWriter.WriteRule(req) {
				// respWriter has been stopped
				break
			}
		}
		return nil
	})
	return respWriter
}

// Notify all open connections for requests with the given userId that a new
// request has been received.
func (p *Prompting) notifyNewRequest(userId int, newRequest *promptrequests.PromptRequest) {
	p.tomb.Go(func() error {
		entry := p.followReqEntryForUser(userId)
		if entry == nil {
			return nil
		}
		// Lock so that new incoming request is not mixed in with the
		// initial outstanding requests.
		entry.lock.Lock()
		defer entry.lock.Unlock()
		for writer := range entry.respWriters {
			// Don't want to block while holding lock, in case one
			// of the requestsChan entries is full.
			p.tomb.Go(func() error {
				writer.WriteRequest(newRequest)
				return nil
			})
		}
		return nil
	})
}

// Notify all open connections for rules with the given userId that a new
// rule has been received.
func (p *Prompting) notifyNewRule(userId int, newRule *accessrules.AccessRule) {
	p.tomb.Go(func() error {
		entry := p.followRuleEntryForUser(userId)
		if entry == nil {
			return nil
		}
		// Lock so that new incoming rule are not mixed in with the
		// initial rules.
		entry.lock.Lock()
		defer entry.lock.Unlock()
		sEntry := entry.snapEntries[newRule.Snap]
		if sEntry == nil {
			return nil
		}
		for writer := range sEntry.respWriters {
			// Don't want to block while holding lock, in case one
			// of the requestsChan entries is full.
			p.tomb.Go(func() error {
				writer.WriteRule(newRule)
				return nil
			})
		}
		saEntry := sEntry.appEntries[newRule.App]
		if saEntry == nil {
			return nil
		}
		for writer := range saEntry.respWriters {
			// Don't want to block while holding lock, in case one
			// of the requestsChan entries is full.
			p.tomb.Go(func() error {
				writer.WriteRule(newRule)
				return nil
			})
		}
		return nil
	})
}

func (p *Prompting) handleListenerReq(req *listener.Request) error {
	// userId := int(req.SubjectUid) // TODO: undo this! This is just for debugging
	userId := userOverride // TODO: undo this! This is just for debugging
	snap, app, err := common.LabelToSnapApp(req.Label)
	if err != nil {
		// the triggering process is not a snap, so treat apparmor label as both snap and app fields
	}

	path := req.Path

	permissions, err := common.PermissionMaskToPermissionsList(req.Permission.(notify.FilePermission))
	if err != nil {
		// some permission bits were unrecognized, ignore them
	}

	satisfiedPerms := make([]common.PermissionType, 0, len(permissions))
	for _, perm := range permissions {
		if yesNo, err := p.rules.IsPathAllowed(userId, snap, app, path, perm); err == nil {
			if !yesNo {
				req.YesNo <- false
				// TODO: the response puts all original permissions in the
				// Deny field, do we want to differentiate the denied bits from
				// the others? Also, do we want to use the waiting listener
				// thread to reply, or construct and send the reply directly?
				return nil
			}
			satisfiedPerms = append(satisfiedPerms, perm)
		}
	}
	if len(satisfiedPerms) == len(permissions) {
		req.YesNo <- true
		return nil
	}

	newRequest := p.requests.Add(userId, snap, app, path, permissions, req.YesNo)
	logger.Noticef("adding request to internal storage: %+v", newRequest)

	p.notifyNewRequest(userId, newRequest)
	return nil
}

func (p *Prompting) Run() error {
	p.tomb.Go(func() error {
		if p.listener == nil {
			logger.Noticef("listener is nil, exiting Prompting.Run() early")
			return nil
		}
		p.tomb.Go(func() error {
			p.listener.Run(&p.tomb)
			logger.Noticef("started listener")
			return nil
		})

		logger.Noticef("ready for prompts")
		for {
			logger.Debugf("waiting prompt loop")
			select {
			case req := <-p.listener.R:
				logger.Noticef("Got from kernel req chan: %v", req)
				if err := p.handleListenerReq(req); err != nil { // no use multithreading, since IsPathAllowed locks
					logger.Noticef("Error while handling request: %v", err)
				}
			case err := <-p.listener.E:
				logger.Noticef("Got from kernel error chan: %v", err)
				return err
			case <-p.tomb.Dying():
				logger.Noticef("Prompting tomb is dying, disconnecting")
				return p.disconnect()
			}
		}
	})
	return nil // TODO: finish this function (is it finished??)
}

func (p *Prompting) Stop() error {
	p.tomb.Kill(nil)
	err := p.tomb.Wait()
	p.listener = nil
	p.requests = nil
	p.rules = nil
	return err
}

func (p *Prompting) GetRequests(userId int) ([]*promptrequests.PromptRequest, error) {
	userId = userOverride // TODO: undo this! This is just for debugging
	reqs := p.requests.Requests(userId)
	return reqs, nil
}

func (p *Prompting) GetRequest(userId int, requestId string) (*promptrequests.PromptRequest, error) {
	userId = userOverride // TODO: undo this! This is just for debugging
	req, err := p.requests.RequestWithId(userId, requestId)
	return req, err
}

type PromptReply struct {
	Outcome     common.OutcomeType      `json:"action"`
	Lifespan    common.LifespanType     `json:"lifespan"`
	Duration    int                     `json:"duration,omitempty"`
	PathPattern string                  `json:"path-pattern"`
	Permissions []common.PermissionType `json:"permissions"`
}

func (p *Prompting) PostRequest(userId int, requestId string, reply *PromptReply) ([]string, error) {
	userId = userOverride // TODO: undo this! This is just for debugging
	req, err := p.requests.Reply(userId, requestId, reply.Outcome)
	if err != nil {
		return nil, err
	}

	// Create new rule based on the reply.
	newRule, err := p.rules.CreateAccessRule(userId, req.Snap, req.App, reply.PathPattern, reply.Outcome, reply.Lifespan, reply.Duration, reply.Permissions)
	if err != nil {
		// XXX: should only occur if identical path to an existing rule with
		// overlapping permissions
		// TODO: extract conflicting permissions, retry CreateAccessRule with
		// conflicting permissions removed
		// TODO: what to do if new reply has different Outcome from previous
		// conflicting rule? Modify old rule to remove conflicting permissions,
		// then re-add new rule? This should probably be built into a version of
		// CreateAccessRule (CreateAccessRuleFromReply ?)
		return nil, err
	}
	p.notifyNewRule(userId, newRule)

	// Apply new rule to outstanding prompt requests.
	satisfiedReqIds, err := p.requests.HandleNewRule(userId, newRule.Snap, newRule.App, newRule.PathPattern, newRule.Outcome, newRule.Permissions)
	if err != nil {
		return nil, err
	}

	return satisfiedReqIds, nil
}

type PostRulesCreateRuleContents struct {
	Snap        string                  `json:"snap"`
	App         string                  `json:"app"`
	PathPattern string                  `json:"path-pattern"`
	Outcome     common.OutcomeType      `json:"outcome"`
	Lifespan    common.LifespanType     `json:"lifespan"`
	Duration    int                     `json:"duration,omitempty"`
	Permissions []common.PermissionType `json:"permissions"`
}

type PostRulesDeleteSelectors struct {
	Snap string `json:"snap"`
	App  string `json:"app,omitempty"`
}

type PostRulesRequestBody struct {
	Action          string                         `json:"action"`
	CreateRules     []*PostRulesCreateRuleContents `json:"rules,omitempty"`
	DeleteSelectors []*PostRulesDeleteSelectors    `json:"selectors,omitempty"`
}

type PostRuleModifyRuleContents struct {
	PathPattern string                  `json:"path-pattern,omitempty"`
	Outcome     common.OutcomeType      `json:"outcome,omitempty"`
	Lifespan    common.LifespanType     `json:"lifespan,omitempty"`
	Duration    int                     `json:"duration,omitempty"`
	Permissions []common.PermissionType `json:"permissions,omitempty"`
}

type PostRuleRequestBody struct {
	Action string                      `json:"action"`
	Rule   *PostRuleModifyRuleContents `json:"rule,omitempty"`
}

func (p *Prompting) GetRules(userId int, snap string, app string) ([]*accessrules.AccessRule, error) {
	userId = userOverride // TODO: undo this! This is just for debugging
	// Daemon already checked that if app != "", then snap != ""
	if app != "" {
		rules := p.rules.RulesForSnapApp(userId, snap, app)
		return rules, nil
	}
	if snap != "" {
		rules := p.rules.RulesForSnap(userId, snap)
		return rules, nil
	}
	rules := p.rules.Rules(userId)
	return rules, nil
}

func (p *Prompting) PostRulesCreate(userId int, rules []*PostRulesCreateRuleContents) ([]*accessrules.AccessRule, error) {
	userId = userOverride // TODO: undo this! This is just for debugging
	createdRules := make([]*accessrules.AccessRule, 0, len(rules))
	errors := make([]error, 0)
	for _, ruleContents := range rules {
		snap := ruleContents.Snap
		app := ruleContents.App
		pathPattern := ruleContents.PathPattern
		outcome := ruleContents.Outcome
		lifespan := ruleContents.Lifespan
		duration := ruleContents.Duration
		permissions := ruleContents.Permissions
		newRule, err := p.rules.CreateAccessRule(userId, snap, app, pathPattern, outcome, lifespan, duration, permissions)
		if err != nil {
			errors = append(errors, err)
		} else {
			createdRules = append(createdRules, newRule)
		}
		p.notifyNewRule(userId, newRule)
	}
	if len(errors) > 0 {
		err := fmt.Errorf("")
		for i, e := range errors {
			err = fmt.Errorf("%w%+v: %v; ", err, rules[i], e)
		}
		return createdRules, err
	}
	return createdRules, nil
}

func (p *Prompting) PostRulesDelete(userId int, deleteSelectors []*PostRulesDeleteSelectors) ([]*accessrules.AccessRule, error) {
	userId = userOverride // TODO: undo this! This is just for debugging
	deletedRules := make([]*accessrules.AccessRule, 0)
	for _, selector := range deleteSelectors {
		snap := selector.Snap
		app := selector.App
		var rulesToDelete []*accessrules.AccessRule
		// Already checked that snap != ""
		if app != "" {
			rulesToDelete = p.rules.RulesForSnapApp(userId, snap, app)
		} else {
			rulesToDelete = p.rules.RulesForSnap(userId, snap)
		}
		for _, rule := range rulesToDelete {
			deletedRule, err := p.rules.DeleteAccessRule(userId, rule.Id)
			if err != nil {
				continue
			}
			deletedRules = append(deletedRules, deletedRule)
		}
	}
	return deletedRules, nil
}

func (p *Prompting) GetRule(userId int, ruleId string) (*accessrules.AccessRule, error) {
	userId = userOverride // TODO: undo this! This is just for debugging
	rule, err := p.rules.RuleWithId(userId, ruleId)
	return rule, err
}

func (p *Prompting) PostRuleModify(userId int, ruleId string, contents *PostRuleModifyRuleContents) (*accessrules.AccessRule, error) {
	userId = userOverride // TODO: undo this! This is just for debugging
	pathPattern := contents.PathPattern
	outcome := contents.Outcome
	lifespan := contents.Lifespan
	duration := contents.Duration
	permissions := contents.Permissions
	rule, err := p.rules.ModifyAccessRule(userId, ruleId, pathPattern, outcome, lifespan, duration, permissions)
	return rule, err
}

func (p *Prompting) PostRuleDelete(userId int, ruleId string) (*accessrules.AccessRule, error) {
	userId = userOverride // TODO: undo this! This is just for debugging
	rule, err := p.rules.DeleteAccessRule(userId, ruleId)
	return rule, err
}
