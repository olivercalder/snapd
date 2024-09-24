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
	"fmt"
	"sort"

	prompting_errors "github.com/snapcore/snapd/interfaces/prompting/errors"
	"github.com/snapcore/snapd/interfaces/prompting/patterns"
	"github.com/snapcore/snapd/logger"
	"github.com/snapcore/snapd/sandbox/apparmor/notify"
	"github.com/snapcore/snapd/strutil"
)

// Constraints hold information about the applicability of a rule to particular
// paths or permissions. A request matches the constraints if the requested path
// is matched by the path pattern (according to bash's globstar matching) and
// the requested permissions are contained in the constraints' permissions.
type Constraints struct {
	PathPattern *patterns.PathPattern  `json:"path-pattern,omitempty"`
	Permissions map[string]OutcomeType `json:"permissions,omitempty"`
}

// ValidateForInterface returns nil if the constraints are valid for the given
// interface, otherwise returns an error.
func (c *Constraints) ValidateForInterface(iface string) error {
	if c.PathPattern == nil {
		return prompting_errors.NewInvalidPathPatternError("", "no path pattern")
	}
	return c.validatePermissions(iface)
}

// validatePermissions checks that the permissions for the given constraints
// are valid for the given interface, and that the outcome for each . If not, returns an error.
func (c *Constraints) validatePermissions(iface string) error {
	availablePerms, ok := interfacePermissionsAvailable[iface]
	if !ok {
		return prompting_errors.NewInvalidInterfaceError(iface, availableInterfaces())
	}
	var invalidPerms []string
	for perm, outcome := range c.Permissions {
		if !strutil.ListContains(availablePerms, perm) {
			invalidPerms = append(invalidPerms, perm)
			continue
		}
		if _, err := outcome.AsBool(); err != nil {
			return fmt.Errorf("invalid outcome for permission %q: %w", perm, err)
		}
	}
	if len(invalidPerms) > 0 {
		return prompting_errors.NewInvalidPermissionsError(iface, invalidPerms, availablePerms)
	}
	if len(permsSet) == 0 {
		return prompting_errors.NewPermissionsListEmptyError(iface, availablePerms)
	}
	return nil
}

// Match returns true if the constraints match the given path, otherwise false.
//
// If the constraints or path are invalid, returns an error.
func (c *Constraints) Match(path string) (bool, error) {
	if c.PathPattern == nil {
		return false, prompting_errors.NewInvalidPathPatternError("", "no path pattern")
	}
	match, err := c.PathPattern.Match(path)
	if err != nil {
		// Error should not occur, since it was parsed internally
		return false, prompting_errors.NewInvalidPathPatternError(c.PathPattern.String(), err.Error())
	}
	return match, nil
}

// ContainPermissions returns true if the constraints include every one of the
// given permissions.
func (c *Constraints) ContainPermissions(permissions []string) bool {
	for _, perm := range permissions {
		if outcome, exists := c.Permissions[perm]; !exists {
			return false
		}
	}
	return true
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
			"read":    notify.AA_MAY_READ | notify.AA_MAY_GETATTR,
			"write":   notify.AA_MAY_WRITE | notify.AA_MAY_APPEND | notify.AA_MAY_CREATE | notify.AA_MAY_DELETE | notify.AA_MAY_RENAME | notify.AA_MAY_SETATTR | notify.AA_MAY_CHMOD | notify.AA_MAY_LOCK | notify.AA_MAY_LINK,
			"execute": notify.AA_MAY_EXEC | notify.AA_EXEC_MMAP,
		},
	}
)

// availableInterfaces returns the list of supported interfaces.
func availableInterfaces() []string {
	interfaces := make([]string, 0, len(interfacePermissionsAvailable))
	for iface := range interfacePermissionsAvailable {
		interfaces = append(interfaces, iface)
	}
	sort.Strings(interfaces)
	return interfaces
}

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
func AbstractPermissionsFromAppArmorPermissions(iface string, permissions any) ([]string, error) {
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
		logger.Noticef("cannot map AppArmor permission to abstract permission for the %s interface: %q", iface, filePerms)
	}
	return abstractPerms, nil
}

// AbstractPermissionsToAppArmorPermissions returns AppArmor permissions
// corresponding to the given permissions for the given interface.
func AbstractPermissionsToAppArmorPermissions(iface string, permissions []string) (any, error) {
	if len(permissions) == 0 {
		availablePerms, _ := AvailablePermissions(iface)
		// Caller should have already validated iface, so no error can occur
		return notify.FilePermission(0), prompting_errors.NewPermissionsListEmptyError(iface, availablePerms)
	}
	filePermsMap, exists := interfaceFilePermissionsMaps[iface]
	if !exists {
		// Should not occur, since we already validated iface and permissions
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
