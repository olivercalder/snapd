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

package udev

import (
	"fmt"
	"sort"
	"strings"

	"github.com/snapcore/snapd/interfaces"
)

type entry struct {
	snippet string
	iface   string
	tag     string
}

// Specification assists in collecting udev snippets associated with an interface.
type Specification struct {
	// Snippets are stored in a map for de-duplication
	snippets map[string]bool
	entries  []entry

	securityTags []string
	iface        string
}

func (spec *Specification) addEntry(snippet, tag string) {
	if spec.snippets == nil {
		spec.snippets = make(map[string]bool)
	}
	if !spec.snippets[snippet] {
		spec.snippets[snippet] = true
		e := entry{
			snippet: snippet,
			iface:   spec.iface,
			tag:     tag,
		}
		spec.entries = append(spec.entries, e)
	}
}

// AddSnippet adds a new udev snippet.
func (spec *Specification) AddSnippet(snippet string) {
	spec.addEntry(snippet, "")
}

func udevTag(securityTag string) string {
	return strings.Replace(securityTag, ".", "_", -1)
}

// TagDevice adds an app/hook specific udev tag to devices described by the snippet.
func (spec *Specification) TagDevice(snippet string) {
	for _, securityTag := range spec.securityTags {
		tag := udevTag(securityTag)
		spec.addEntry(fmt.Sprintf(`%s, TAG+="%s" # %s`, snippet, tag, spec.iface), tag)
	}
}

type byTagAndSnippet []entry

func (c byTagAndSnippet) Len() int      { return len(c) }
func (c byTagAndSnippet) Swap(i, j int) { c[i], c[j] = c[j], c[i] }
func (c byTagAndSnippet) Less(i, j int) bool {
	if c[i].tag != c[j].tag {
		return c[i].tag < c[j].tag
	}
	return c[i].snippet < c[j].snippet
}

// Snippets returns a copy of all the snippets added so far.
func (spec *Specification) Snippets() (result []string) {
	entries := make([]entry, len(spec.entries))
	copy(entries, spec.entries)
	sort.Sort(byTagAndSnippet(entries))

	result = make([]string, 0, len(spec.entries))
	for _, entry := range entries {
		result = append(result, entry.snippet)
	}
	return result
}

// Implementation of methods required by interfaces.Specification

// AddConnectedPlug records udev-specific side-effects of having a connected plug.
func (spec *Specification) AddConnectedPlug(iface interfaces.Interface, plug *interfaces.Plug, plugAttrs map[string]interface{}, slot *interfaces.Slot, slotAttrs map[string]interface{}) error {
	type definer interface {
		UDevConnectedPlug(spec *Specification, plug *interfaces.Plug, plugAttrs map[string]interface{}, slot *interfaces.Slot, slotAttrs map[string]interface{}) error
	}
	ifname := iface.Name()
	if iface, ok := iface.(definer); ok {
		spec.securityTags = plug.SecurityTags()
		spec.iface = ifname
		defer func() { spec.securityTags = nil; spec.iface = "" }()
		return iface.UDevConnectedPlug(spec, plug, plugAttrs, slot, slotAttrs)
	}
	return nil
}

// AddConnectedSlot records mount-specific side-effects of having a connected slot.
func (spec *Specification) AddConnectedSlot(iface interfaces.Interface, plug *interfaces.Plug, plugAttrs map[string]interface{}, slot *interfaces.Slot, slotAttrs map[string]interface{}) error {
	type definer interface {
		UDevConnectedSlot(spec *Specification, plug *interfaces.Plug, plugAttrs map[string]interface{}, slot *interfaces.Slot, slotAttrs map[string]interface{}) error
	}
	ifname := iface.Name()
	if iface, ok := iface.(definer); ok {
		spec.securityTags = slot.SecurityTags()
		spec.iface = ifname
		defer func() { spec.securityTags = nil; spec.iface = "" }()
		return iface.UDevConnectedSlot(spec, plug, plugAttrs, slot, slotAttrs)
	}
	return nil
}

// AddPermanentPlug records mount-specific side-effects of having a plug.
func (spec *Specification) AddPermanentPlug(iface interfaces.Interface, plug *interfaces.Plug) error {
	type definer interface {
		UDevPermanentPlug(spec *Specification, plug *interfaces.Plug) error
	}
	ifname := iface.Name()
	if iface, ok := iface.(definer); ok {
		spec.securityTags = plug.SecurityTags()
		spec.iface = ifname
		defer func() { spec.securityTags = nil; spec.iface = "" }()
		return iface.UDevPermanentPlug(spec, plug)
	}
	return nil
}

// AddPermanentSlot records mount-specific side-effects of having a slot.
func (spec *Specification) AddPermanentSlot(iface interfaces.Interface, slot *interfaces.Slot) error {
	type definer interface {
		UDevPermanentSlot(spec *Specification, slot *interfaces.Slot) error
	}
	ifname := iface.Name()
	if iface, ok := iface.(definer); ok {
		spec.securityTags = slot.SecurityTags()
		spec.iface = ifname
		defer func() { spec.securityTags = nil; spec.iface = "" }()
		return iface.UDevPermanentSlot(spec, slot)
	}
	return nil
}
