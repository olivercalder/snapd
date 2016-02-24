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

package client_test

import (
	"encoding/json"

	"gopkg.in/check.v1"

	"github.com/ubuntu-core/snappy/client"
)

func (cs *clientSuite) TestClientAllPlugsCallsEndpoint(c *check.C) {
	_, _ = cs.cli.AllPlugs()
	c.Check(cs.req.Method, check.Equals, "GET")
	c.Check(cs.req.URL.Path, check.Equals, "/2.0/skills")
}

func (cs *clientSuite) TestClientAllPlugs(c *check.C) {
	cs.rsp = `{
		"type": "sync",
		"result": [
			{
				"snap": "canonical-pi2",
				"name": "pin-13",
				"type": "bool-file",
				"label": "Pin 13",
				"granted_to": [
					{"snap": "keyboard-lights", "name": "capslock-led"}
				]
			}
		]
	}`
	skills, err := cs.cli.AllPlugs()
	c.Assert(err, check.IsNil)
	c.Check(skills, check.DeepEquals, []client.PlugConnections{
		{
			Plug: client.Plug{
				Snap:      "canonical-pi2",
				Name:      "pin-13",
				Interface: "bool-file",
				Label:     "Pin 13",
			},
			Connections: []client.Slot{
				{
					Snap: "keyboard-lights",
					Name: "capslock-led",
				},
			},
		},
	})
}

func (cs *clientSuite) TestClientConnectCallsEndpoint(c *check.C) {
	_ = cs.cli.Connect("producer", "skill", "consumer", "slot")
	c.Check(cs.req.Method, check.Equals, "POST")
	c.Check(cs.req.URL.Path, check.Equals, "/2.0/skills")
}

func (cs *clientSuite) TestClientConnect(c *check.C) {
	cs.rsp = `{
		"type": "sync",
		"result": { }
	}`
	err := cs.cli.Connect("producer", "skill", "consumer", "slot")
	c.Check(err, check.IsNil)
	var body map[string]interface{}
	decoder := json.NewDecoder(cs.req.Body)
	err = decoder.Decode(&body)
	c.Check(err, check.IsNil)
	c.Check(body, check.DeepEquals, map[string]interface{}{
		"action": "grant",
		"skill": map[string]interface{}{
			"snap": "producer",
			"name": "skill",
		},
		"slot": map[string]interface{}{
			"snap": "consumer",
			"name": "slot",
		},
	})
}

func (cs *clientSuite) TestClientDisconnectCallsEndpoint(c *check.C) {
	_ = cs.cli.Disconnect("producer", "skill", "consumer", "slot")
	c.Check(cs.req.Method, check.Equals, "POST")
	c.Check(cs.req.URL.Path, check.Equals, "/2.0/skills")
}

func (cs *clientSuite) TestClientDisconnect(c *check.C) {
	cs.rsp = `{
		"type": "sync",
		"result": { }
	}`
	err := cs.cli.Disconnect("producer", "skill", "consumer", "slot")
	c.Check(err, check.IsNil)
	var body map[string]interface{}
	decoder := json.NewDecoder(cs.req.Body)
	err = decoder.Decode(&body)
	c.Check(err, check.IsNil)
	c.Check(body, check.DeepEquals, map[string]interface{}{
		"action": "revoke",
		"skill": map[string]interface{}{
			"snap": "producer",
			"name": "skill",
		},
		"slot": map[string]interface{}{
			"snap": "consumer",
			"name": "slot",
		},
	})
}

func (cs *clientSuite) TestClientAddPlugCallsEndpoint(c *check.C) {
	_ = cs.cli.AddPlug(&client.Plug{})
	c.Check(cs.req.Method, check.Equals, "POST")
	c.Check(cs.req.URL.Path, check.Equals, "/2.0/skills")
}

func (cs *clientSuite) TestClientAddPlug(c *check.C) {
	cs.rsp = `{
		"type": "sync",
		"result": { }
	}`
	err := cs.cli.AddPlug(&client.Plug{
		Snap:      "snap",
		Name:      "name",
		Interface: "type",
		Attrs: map[string]interface{}{
			"attr": "value",
		},
		Apps:  []string{"app"},
		Label: "label",
	})
	c.Check(err, check.IsNil)
	var body map[string]interface{}
	decoder := json.NewDecoder(cs.req.Body)
	err = decoder.Decode(&body)
	c.Check(err, check.IsNil)
	c.Check(body, check.DeepEquals, map[string]interface{}{
		"action": "add-skill",
		"skill": map[string]interface{}{
			"name": "name",
			"snap": "snap",
			"type": "type",
			"attrs": map[string]interface{}{
				"attr": "value",
			},
			"apps":  []interface{}{"app"},
			"label": "label",
		},
	})
}

func (cs *clientSuite) TestClientRemovePlugCallsEndpoint(c *check.C) {
	_ = cs.cli.RemovePlug("snap", "name")
	c.Check(cs.req.Method, check.Equals, "POST")
	c.Check(cs.req.URL.Path, check.Equals, "/2.0/skills")
}

func (cs *clientSuite) TestClientRemovePlug(c *check.C) {
	cs.rsp = `{
		"type": "sync",
		"result": { }
	}`
	err := cs.cli.RemovePlug("snap", "name")
	c.Check(err, check.IsNil)
	var body map[string]interface{}
	decoder := json.NewDecoder(cs.req.Body)
	err = decoder.Decode(&body)
	c.Check(err, check.IsNil)
	c.Check(body, check.DeepEquals, map[string]interface{}{
		"action": "remove-skill",
		"skill": map[string]interface{}{
			"name": "name",
			"snap": "snap",
		},
	})
}

func (cs *clientSuite) TestClientAddSlotCallsEndpoint(c *check.C) {
	_ = cs.cli.AddSlot(&client.Slot{})
	c.Check(cs.req.Method, check.Equals, "POST")
	c.Check(cs.req.URL.Path, check.Equals, "/2.0/skills")
}

func (cs *clientSuite) TestClientAddSlot(c *check.C) {
	cs.rsp = `{
		"type": "sync",
		"result": { }
	}`
	err := cs.cli.AddSlot(&client.Slot{
		Snap:      "snap",
		Name:      "name",
		Interface: "type",
		Attrs: map[string]interface{}{
			"attr": "value",
		},
		Apps:  []string{"app"},
		Label: "label",
	})
	c.Check(err, check.IsNil)
	var body map[string]interface{}
	decoder := json.NewDecoder(cs.req.Body)
	err = decoder.Decode(&body)
	c.Check(err, check.IsNil)
	c.Check(body, check.DeepEquals, map[string]interface{}{
		"action": "add-slot",
		"slot": map[string]interface{}{
			"name": "name",
			"snap": "snap",
			"type": "type",
			"attrs": map[string]interface{}{
				"attr": "value",
			},
			"apps":  []interface{}{"app"},
			"label": "label",
		},
	})
}

func (cs *clientSuite) TestClientRemoveSlotCallsEndpoint(c *check.C) {
	_ = cs.cli.RemoveSlot("snap", "name")
	c.Check(cs.req.Method, check.Equals, "POST")
	c.Check(cs.req.URL.Path, check.Equals, "/2.0/skills")
}

func (cs *clientSuite) TestClientRemoveSlot(c *check.C) {
	cs.rsp = `{
		"type": "sync",
		"result": { }
	}`
	err := cs.cli.RemoveSlot("snap", "name")
	c.Check(err, check.IsNil)
	var body map[string]interface{}
	decoder := json.NewDecoder(cs.req.Body)
	err = decoder.Decode(&body)
	c.Check(err, check.IsNil)
	c.Check(body, check.DeepEquals, map[string]interface{}{
		"action": "remove-slot",
		"slot": map[string]interface{}{
			"name": "name",
			"snap": "snap",
		},
	})
}
