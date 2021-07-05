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

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/snapcore/snapd/jsonutil"
	"github.com/snapcore/snapd/overlord/state"
)

// Transaction holds a copy of the configuration originally present in the
// provided state which can be queried and mutated in isolation from
// concurrent logic. All changes performed into it are persisted back into
// the state at once when Commit is called.
//
// Transactions are safe to access and modify concurrently.
type Transaction struct {
	mu       sync.Mutex
	state    *state.State
	pristine map[string]map[string]*json.RawMessage // snap => key => value
	changes  map[string]map[string]interface{}
}

// NewTransaction creates a new configuration transaction initialized with the given state.
//
// The provided state must be locked by the caller.
func NewTransaction(st *state.State) *Transaction {
	transaction := &Transaction{state: st}
	transaction.changes = make(map[string]map[string]interface{})

	// Record the current state of the map containing the config of every snap
	// in the system. We'll use it for this transaction.
	err := st.Get("config", &transaction.pristine)
	if err == state.ErrNoState {
		transaction.pristine = make(map[string]map[string]*json.RawMessage)
	} else if err != nil {
		panic(fmt.Errorf("internal error: cannot unmarshal configuration: %v", err))
	}
	return transaction
}

// State returns the system State
func (t *Transaction) State() *state.State {
	return t.state
}

func changes(cfgStr string, cfg map[string]interface{}) []string {
	var out []string
	for k := range cfg {
		switch subCfg := cfg[k].(type) {
		case map[string]interface{}:
			out = append(out, changes(cfgStr+"."+k, subCfg)...)
		case *json.RawMessage:
			// check if we need to dive into a sub-config
			var configm map[string]interface{}
			if err := jsonutil.DecodeWithNumber(bytes.NewReader(*subCfg), &configm); err == nil {
				// curiously, json decoder decodes json.RawMessage("null") into a nil map, so no change is
				// reported when we recurse into it. This happens when unsetting a key and the underlying
				// config path doesn't exist.
				if len(configm) > 0 {
					out = append(out, changes(cfgStr+"."+k, configm)...)
					continue
				}
			}
			out = append(out, []string{cfgStr + "." + k}...)
		default:
			out = append(out, []string{cfgStr + "." + k}...)
		}
	}
	return out
}

// Changes returns the changing keys associated with this transaction
func (t *Transaction) Changes() []string {
	var out []string
	for k := range t.changes {
		out = append(out, changes(k, t.changes[k])...)
	}
	sort.Strings(out)
	return out
}

// shadowsVirtualConfig checks that the given subkeys/value does not
// "block" the path to a virtual config with a non-map type. E.g. if
// "network.netplan" is virtual it must be impossible to set
// "network=false" or getting the document under "network" would be
// wrong.
func shadowsVirtualConfig(instanceName string, subkeys []string, value interface{}) error {
	// maps never block the path
	if v := reflect.ValueOf(value); v.Kind() == reflect.Map {
		return nil
	}

	// helper to compare if two subkeys slices have a common prefix
	keysHaveCommonPrefix := func(s, prefix []string) bool {
		if len(prefix) > len(s) {
			return false
		}
		for i := range prefix {
			if prefix[i] != s[i] {
				return false
			}
		}
		return true
	}

	virtualMu.Lock()
	km, ok := virtualMap[instanceName]
	virtualMu.Unlock()
	if ok {
		for virtualKey := range km {
			virtualSubKeys, err := ParseKey(virtualKey)
			if err != nil {
				fmt.Errorf("internal error: invalid virtual configuration: %v", err)
			}
			if len(virtualSubKeys) > len(subkeys) && keysHaveCommonPrefix(virtualSubKeys, subkeys) {
				return fmt.Errorf("cannot set %q for %q to non-map value because %q is a virtual configuration", strings.Join(subkeys, "."), instanceName, virtualKey)
			}
			//}
		}
	}

	return nil
}

// Set sets the provided snap's configuration key to the given value.
// The provided key may be formed as a dotted key path through nested maps.
// For example, the "a.b.c" key describes the {a: {b: {c: value}}} map.
// When the key is provided in that form, intermediate maps are mutated
// rather than replaced, and created when necessary.
//
// The provided value must marshal properly by encoding/json.
// Changes are not persisted until Commit is called.
func (t *Transaction) Set(instanceName, key string, value interface{}) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	config := t.changes[instanceName]
	if config == nil {
		config = make(map[string]interface{})
	}

	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("cannot marshal snap %q option %q: %s", instanceName, key, err)
	}
	raw := json.RawMessage(data)

	subkeys, err := ParseKey(key)
	if err != nil {
		return err
	}

	// Check whether it's trying to traverse a non-map from pristine. This
	// would go unperceived by the configuration patching below.
	if len(subkeys) > 1 {
		var result interface{}
		err = getFromConfig(instanceName, subkeys, 0, t.pristine[instanceName], &result)
		if err != nil && !IsNoOption(err) {
			return err
		}
	}
	// check that we do not "block" a path to virtual config with non-maps
	if err := shadowsVirtualConfig(instanceName, subkeys, value); err != nil {
		return err
	}

	// config here is never nil and PatchConfig always operates
	// directly on and returns config if it's a
	// map[string]interface{}
	_, err = PatchConfig(instanceName, subkeys, 0, config, &raw)
	if err != nil {
		return err
	}

	t.changes[instanceName] = config
	return nil
}

func (t *Transaction) copyPristine(snapName string) map[string]*json.RawMessage {
	out := make(map[string]*json.RawMessage)
	if config, ok := t.pristine[snapName]; ok {
		for k, v := range config {
			out[k] = v
		}
	}
	return out
}

// Get unmarshals into result the cached value of the provided snap's configuration key.
// If the key does not exist, an error of type *NoOptionError is returned.
// The provided key may be formed as a dotted key path through nested maps.
// For example, the "a.b.c" key describes the {a: {b: {c: value}}} map.
//
// Transactions do not see updates from the current state or from other transactions.
func (t *Transaction) Get(snapName, key string, result interface{}) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	subkeys, err := ParseKey(key)
	if err != nil {
		return err
	}

	// merge virtual config and then commit changes onto a copy of pristine configuration, so that get has a complete view of the config.
	config := t.copyPristine(snapName)
	// 1. merge virtual
	mergedConfig, err := mergeConfigWithVirtual(snapName, jsonRaw(config))
	if err != nil {
		return err
	}
	if err := jsonutil.DecodeWithNumber(bytes.NewReader(*mergedConfig), &config); err != nil {
		return err
	}
	// 2. apply changes
	applyChanges(config, t.changes[snapName])

	purgeNulls(config)
	return getFromConfig(snapName, subkeys, 0, config, result)
}

// GetMaybe unmarshals into result the cached value of the provided snap's configuration key.
// If the key does not exist, no error is returned.
//
// Transactions do not see updates from the current state or from other transactions.
func (t *Transaction) GetMaybe(instanceName, key string, result interface{}) error {
	err := t.Get(instanceName, key, result)
	if err != nil && !IsNoOption(err) {
		return err
	}
	return nil
}

// GetPristine unmarshals the cached pristine (before applying any
// changes) value of the provided snap's configuration key into
// result.
//
// If the key does not exist, an error of type *NoOptionError is returned.
func (t *Transaction) GetPristine(snapName, key string, result interface{}) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	subkeys, err := ParseKey(key)
	if err != nil {
		return err
	}

	return getFromConfig(snapName, subkeys, 0, t.pristine[snapName], result)
}

// GetPristineMaybe unmarshals the cached pristine (before applying any
// changes) value of the provided snap's configuration key into
// result.
//
// If the key does not exist, no error is returned.
func (t *Transaction) GetPristineMaybe(instanceName, key string, result interface{}) error {
	err := t.GetPristine(instanceName, key, result)
	if err != nil && !IsNoOption(err) {
		return err
	}
	return nil
}

func getFromConfig(instanceName string, subkeys []string, pos int, config map[string]*json.RawMessage, result interface{}) error {
	// special case - get root document
	if len(subkeys) == 0 {
		if len(config) == 0 {
			return &NoOptionError{SnapName: instanceName}
		}
		raw := jsonRaw(config)
		if err := jsonutil.DecodeWithNumber(bytes.NewReader(*raw), &result); err != nil {
			return fmt.Errorf("internal error: cannot unmarshal snap %q root document: %s", instanceName, err)
		}
		return nil
	}

	raw, ok := config[subkeys[pos]]
	if !ok {
		return &NoOptionError{SnapName: instanceName, Key: strings.Join(subkeys[:pos+1], ".")}
	}

	// There is a known problem with json raw messages representing nulls when they are stored in nested structures, such as
	// config map inside our state. These are turned into nils and need to be handled explicitly.
	if raw == nil {
		m := json.RawMessage("null")
		raw = &m
	}

	if pos+1 == len(subkeys) {
		if err := jsonutil.DecodeWithNumber(bytes.NewReader(*raw), &result); err != nil {
			key := strings.Join(subkeys, ".")
			return fmt.Errorf("internal error: cannot unmarshal snap %q option %q into %T: %s, json: %s", instanceName, key, result, err, *raw)
		}
		return nil
	}

	var configm map[string]*json.RawMessage
	if err := jsonutil.DecodeWithNumber(bytes.NewReader(*raw), &configm); err != nil {
		return fmt.Errorf("snap %q option %q is not a map", instanceName, strings.Join(subkeys[:pos+1], "."))
	}
	return getFromConfig(instanceName, subkeys, pos+1, configm, result)
}

// Commit applies to the state the configuration changes made in the transaction
// and updates the observed configuration to the result of the operation.
//
// The state associated with the transaction must be locked by the caller.
func (t *Transaction) Commit() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(t.changes) == 0 {
		return
	}

	// Update our copy of the config with the most recent one from the state.
	err := t.state.Get("config", &t.pristine)
	if err == state.ErrNoState {
		t.pristine = make(map[string]map[string]*json.RawMessage)
	} else if err != nil {
		panic(fmt.Errorf("internal error: cannot unmarshal configuration: %v", err))
	}

	// Iterate through the write cache and save each item but exclude virtual configuration
	for instanceName, snapChanges := range t.changes {
		for k, v := range snapChanges {
			clearVirtualConfig(instanceName, v, k, 0)
		}

		config := t.pristine[instanceName]
		// due to LP #1917870 we might have a hook configure task in flight
		// that tries to apply config over nil map, create it if nil.
		if config == nil {
			config = make(map[string]*json.RawMessage)
		}
		applyChanges(config, snapChanges)
		purgeNulls(config)
		t.pristine[instanceName] = config
	}

	t.state.Set("config", t.pristine)

	// The cache has been flushed, reset it.
	t.changes = make(map[string]map[string]interface{})
}

func applyChanges(config map[string]*json.RawMessage, changes map[string]interface{}) {
	for k, v := range changes {
		config[k] = commitChange(config[k], v)
	}
}

func jsonRaw(v interface{}) *json.RawMessage {
	data, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Errorf("internal error: cannot marshal configuration: %v", err))
	}
	raw := json.RawMessage(data)
	return &raw
}

func commitChange(pristine *json.RawMessage, change interface{}) *json.RawMessage {
	switch change := change.(type) {
	case *json.RawMessage:
		return change
	case map[string]interface{}:
		if pristine == nil {
			return jsonRaw(change)
		}
		var pristinem map[string]*json.RawMessage
		if err := jsonutil.DecodeWithNumber(bytes.NewReader(*pristine), &pristinem); err != nil {
			// Not a map. Overwrite with the change.
			return jsonRaw(change)
		}
		for k, v := range change {
			pristinem[k] = commitChange(pristinem[k], v)
		}
		return jsonRaw(pristinem)
	}
	panic(fmt.Errorf("internal error: unexpected configuration type %T", change))
}

// mergeConfigWithVirtual takes the given configuration and merges it
// with the virtual configuration values by calling the registered
// virtual configuration function of the given snap. The merged config
// is returned.
func mergeConfigWithVirtual(instanceName string, config *json.RawMessage) (*json.RawMessage, error) {
	virtualMu.Lock()
	km, ok := virtualMap[instanceName]
	virtualMu.Unlock()
	if !ok {
		return config, nil
	}

	// create a "patch" from the virtual entries
	patch := make(map[string]interface{})
	for key, virtualFn := range km {
		if virtualFn == nil {
			continue
		}
		res, err := virtualFn(instanceName, key)
		if err != nil {
			return nil, err
		}
		patch[key] = jsonRaw(res)
	}

	// and apply that on top of the config
	patchKeys := sortPatchKeysByDepth(patch)
	for _, subkeys := range patchKeys {
		raw := jsonRaw(patch[subkeys])
		mergedConfig, err := PatchConfig(instanceName, strings.Split(subkeys, "."), 0, config, raw)
		if err != nil {
			return nil, err
		}
		config = jsonRaw(mergedConfig)
	}

	return config, nil
}

// clearVirtualConfig iterates over a given config and removes any values
// that come from virtual configuration. This is used before commiting a
// config to disk.
func clearVirtualConfig(instanceName string, config interface{}, subkeys string, depth int) {
	virtualMu.Lock()
	km, ok := virtualMap[instanceName]
	virtualMu.Unlock()
	if !ok {
		return
	}

	switch config := config.(type) {
	case map[string]interface{}:
		for k, v := range config {
			key := subkeys + "." + k
			if _, ok := km[key]; ok {
				delete(config, k)
				return
			}
			clearVirtualConfig(instanceName, v, subkeys+"."+k, depth+1)
		}
	}
}

// IsNoOption returns whether the provided error is a *NoOptionError.
func IsNoOption(err error) bool {
	_, ok := err.(*NoOptionError)
	return ok
}

// NoOptionError indicates that a config option is not set.
type NoOptionError struct {
	SnapName string
	Key      string
}

func (e *NoOptionError) Error() string {
	if e.Key == "" {
		return fmt.Sprintf("snap %q has no configuration", e.SnapName)
	}
	return fmt.Sprintf("snap %q has no %q configuration option", e.SnapName, e.Key)
}

// VirtualCfgFunc can be used for virtual "transaction.Get()" calls
type VirtualCfgFunc func(snapName, key string) (result interface{}, err error)

// virtualMap contain "virtual" configuration keys like
// e.g. "core.hostname".  The data is never stored in the state but
// instead directly get/set.
var (
	virtualMap map[string]map[string]VirtualCfgFunc
	virtualMu  sync.Mutex
)

func RegisterVirtualConfig(snapName, key string, hi VirtualCfgFunc) {
	virtualMu.Lock()
	defer virtualMu.Unlock()

	if virtualMap == nil {
		virtualMap = make(map[string]map[string]VirtualCfgFunc)
	}
	if _, ok := virtualMap[snapName]; !ok {
		virtualMap[snapName] = make(map[string]VirtualCfgFunc)
	}
	virtualMap[snapName][key] = hi
}
