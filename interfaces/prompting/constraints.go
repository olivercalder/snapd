// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
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

package prompting

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"

	"github.com/snapcore/snapd/sandbox/apparmor/notify"
)

var (
	ErrPermissionNotInList        = errors.New("permission not found in permissions list")
	ErrPermissionsListEmpty       = errors.New("permissions list empty")
	ErrUnrecognizedFilePermission = errors.New("file permissions mask contains unrecognized permission")
)

type Permissions uint32

// Count returns the number of contained permissions.
func (p Permissions) Count() int {
	return bits.OnesCount32(uint32(p))
}

// Contain returns true if the given other permissions are a subset of the
// receiver.
func (p Permissions) Contain(other Permissions) bool {
	shared := p & other
	return shared == other
}

// Subtract removes all of the given other permissions from those of the
// receiver, if they have any in common. Returns whether at least one permission
// was removed, and whether all permissions were removed.
func (p *Permissions) Subtract(other Permissions) (modified, satisfied bool) {
	old := *p
	*p &= ^other
	modified = *p != old
	satisfied = *p == 0
	return modified, satisfied
}

// AsList returns the permissions as a list of strings based on the available
// permissions for the given interface.
func (p Permissions) AsList(iface string) []string {
	availablePerms, ok := interfacePermissionsAvailable[iface]
	if !ok {
		panic(fmt.Sprintf("cannot convert permissions to list for invalid interface: %s", iface))
	}
	permStrings := make([]string, 0, p.Count())
	for remaining := p; remaining != 0; remaining = remaining & (remaining - 1) {
		next := bits.TrailingZeros32(uint32(remaining))
		permStrings = append(permStrings, availablePerms[next])
	}
	return permStrings
}

// PermissionsFromList converts the given list of permissions for the given
// interface to Permissions.
func PermissionsFromList(iface string, perms []string) (Permissions, error) {
	availablePerms, ok := interfacePermissionsAvailable[iface]
	if !ok {
		return 0, fmt.Errorf("unsupported interface: %s", iface)
	}
	permissions := Permissions(0)
permsLoop:
	for _, perm := range perms {
		for i, ap := range availablePerms {
			if ap == perm {
				permissions |= 1 << i
				continue permsLoop
			}
		}
		return 0, fmt.Errorf("unsupported permission for %s interface: %q", iface, perm)
	}
	if permissions == 0 {
		return 0, ErrPermissionsListEmpty
	}
	return permissions, nil
}

type Constraints struct {
	PathPattern string
	Permissions Permissions
}

// Equal returns true if the given other constraints are equal to the receiver.
func (c *Constraints) Equal(other *Constraints) bool {
	return c.PathPattern == other.PathPattern && c.Permissions == other.Permissions
}

// Match returns true if the constraints match the given path, otherwise false.
//
// If the constraints or path are invalid, returns an error.
func (c *Constraints) Match(path string) (bool, error) {
	return PathPatternMatch(c.PathPattern, path)
}

// jsonConstraints exists so that we can control how constraints are marshalled
// to JSON.
type jsonConstraints struct {
	PathPattern string   `json:"path-pattern,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// MarshalJSONForInterface is necessary so that structs containing Constraints
// can be marshalled to JSON, which requires providing a known interface.
func (c *Constraints) MarshalJSONForInterface(iface string) ([]byte, error) {
	jc := jsonConstraints{
		PathPattern: c.PathPattern,
		Permissions: c.Permissions.AsList(iface),
	}
	return json.Marshal(jc)
}

// UnmarshalJSONForInterface is necessary so that structs containing Constraints
// can be unmarshalled from JSON, which requires providing a known interface.
func (c *Constraints) UnmarshalJSONForInterface(iface string, data []byte) error {
	var jc jsonConstraints
	err := json.Unmarshal(data, &jc)
	if err != nil {
		return err
	}
	c.PathPattern = jc.PathPattern
	c.Permissions, err = PermissionsFromList(iface, jc.Permissions)
	if err != nil {
		return err
	}
	return nil
}

var (
	// List of permissions available for each interface. This also defines the
	// order in which the permissions should be presented.
	interfacePermissionsAvailable = map[string][]string{
		"home": {"read", "write", "execute"},
	}

	// A mapping from interfaces which support AppArmor file permissions to
	// the map between abstract permissions and those file permissions.
	//
	// Never include AA_MAY_OPEN in the maps below; it should always come from
	// the kernel with another permission (e.g. AA_MAY_READ or AA_MAY_WRITE),
	// and if it does not, it should be interpreted as AA_MAY_READ.
	interfaceFilePermissionsMaps = map[string]map[string]notify.FilePermission{
		"home": {
			"read":    notify.AA_MAY_READ,
			"write":   notify.AA_MAY_WRITE | notify.AA_MAY_APPEND | notify.AA_MAY_CREATE | notify.AA_MAY_DELETE | notify.AA_MAY_RENAME | notify.AA_MAY_CHMOD | notify.AA_MAY_LOCK | notify.AA_MAY_LINK,
			"execute": notify.AA_MAY_EXEC | notify.AA_EXEC_MMAP,
		},
	}
)

// AvailablePermissions returns the list of available permissions for the given
// interface.
func AvailablePermissions(iface string) ([]string, error) {
	available, exist := interfacePermissionsAvailable[iface]
	if !exist {
		return nil, fmt.Errorf("cannot get available permissions: unsupported interface: %s", iface)
	}
	return available, nil
}

// AbstractPermissionsFromAppArmorPermissions returns the list of permissions
// corresponding to the given AppArmor permissions for the given interface.
func AbstractPermissionsFromAppArmorPermissions(iface string, permissions interface{}) ([]string, error) {
	filePerms, ok := permissions.(notify.FilePermission)
	if !ok {
		return nil, fmt.Errorf("cannot parse the given permissions as file permissions: %v", permissions)
	}
	if filePerms == notify.FilePermission(0) {
		return nil, fmt.Errorf("cannot get abstract permissions from empty AppArmor permissions: %q", filePerms)
	}
	abstractPermsAvailable, exists := interfacePermissionsAvailable[iface]
	if !exists {
		return nil, fmt.Errorf("cannot map the given interface to list of available permissions: %s", iface)
	}
	abstractPermsMap, exists := interfaceFilePermissionsMaps[iface]
	if !exists {
		// This should never happen, since we just found a permissions list
		// for the given interface and thus a map should exist for it as well.
		return nil, fmt.Errorf("cannot map the given interface to map from abstract permissions to AppArmor permissions: %s", iface)
	}
	if filePerms == notify.AA_MAY_OPEN {
		// Should not occur, but if a request is received for only open, treat it as read.
		filePerms = notify.AA_MAY_READ
	}
	// Discard Open permission; re-add it to the permission mask later
	filePerms &= ^notify.AA_MAY_OPEN
	abstractPerms := make([]string, 0, 1) // most requests should only include one permission
	for _, abstractPerm := range abstractPermsAvailable {
		aaPermMapping, exists := abstractPermsMap[abstractPerm]
		if !exists {
			// This should never happen, since permission mappings are
			// predefined and should be checked for correctness.
			return nil, fmt.Errorf("internal error: cannot map abstract permission to AppArmor permissions for the %s interface: %q", iface, abstractPerm)
		}
		if filePerms&aaPermMapping != 0 {
			abstractPerms = append(abstractPerms, abstractPerm)
			filePerms &= ^aaPermMapping
		}
	}
	if filePerms != notify.FilePermission(0) {
		return nil, fmt.Errorf("cannot map AppArmor permission to abstract permission for the %s interface: %q", iface, filePerms)
	}
	return abstractPerms, nil
}

// AbstractPermissionsToAppArmorPermissions returns AppArmor permissions
// corresponding to the given permissions for the given interface.
func AbstractPermissionsToAppArmorPermissions(iface string, permissions []string) (interface{}, error) {
	if len(permissions) == 0 {
		return notify.FilePermission(0), ErrPermissionsListEmpty
	}
	filePermsMap, exists := interfaceFilePermissionsMaps[iface]
	if !exists {
		return notify.FilePermission(0), fmt.Errorf("cannot map the given interface to map from abstract permissions to AppArmor permissions: %s", iface)
	}
	filePerms := notify.FilePermission(0)
	for _, perm := range permissions {
		permMask, exists := filePermsMap[perm]
		if !exists {
			// Should not occur, since stored permissions list should have been validated
			return notify.FilePermission(0), fmt.Errorf("cannot map abstract permission to AppArmor permissions for the %s interface: %q", iface, perm)
		}
		filePerms |= permMask
	}
	if filePerms&(notify.AA_MAY_EXEC|notify.AA_MAY_WRITE|notify.AA_MAY_READ|notify.AA_MAY_APPEND|notify.AA_MAY_CREATE) != 0 {
		filePerms |= notify.AA_MAY_OPEN
	}
	return filePerms, nil
}
