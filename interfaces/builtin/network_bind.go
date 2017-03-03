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

package builtin

import (
	"github.com/snapcore/snapd/interfaces"
)

// http://bazaar.launchpad.net/~ubuntu-security/ubuntu-core-security/trunk/view/head:/data/apparmor/policygroups/ubuntu-core/16.04/network-bind
const networkBindConnectedPlugAppArmor = `
# Description: Can access the network as a server.
#include <abstractions/nameservice>
#include <abstractions/ssl_certs>

# These probably shouldn't be something that apps should use, but this offers
# no information disclosure since the files are in the read-only part of the
# system.
/etc/hosts.deny r,
/etc/hosts.allow r,

@{PROC}/sys/net/core/somaxconn r,
@{PROC}/sys/net/ipv4/ip_local_port_range r,

# LP: #1496906: java apps need these for some reason and they leak the IPv6 IP
# addresses and routes. Until we find another way to handle them (see the bug
# for some options), we need to allow them to avoid developer confusion.
@{PROC}/@{pid}/net/if_inet6 r,
@{PROC}/@{pid}/net/ipv6_route r,

# java apps attempt this, presumably to handle interface changes, but a
# corresponding seccomp socket rule is required to use netlink. When
# fine-grained netlink mediation is implemented (LP: #1669552), we can perhaps
# allow 'read' with NETLINK_ROUTE, but for now we omit it here and don't
# explicitly deny this noisy denial so --devmode isn't broken. LP: #1499897
#deny network netlink dgram,
`

// http://bazaar.launchpad.net/~ubuntu-security/ubuntu-core-security/trunk/view/head:/data/seccomp/policygroups/ubuntu-core/16.04/network-bind
const networkBindConnectedPlugSecComp = `
# Description: Can access the network as a server.
accept
accept4
bind
listen
shutdown
# TODO: remove this rule once seccomp errno with logging is implemented.
# java apps attempt this, presumably to handle interface changes, but a
# corresponding AppArmor rule is required (eg, network netlink dgram) to use
# netlink. We allow it here but not network-bind policy for AppArmor since java
# falls back gracefully when faced with an EPERM. Without this rule, the
# application would be KILLed due to out default seccomp policy.
socket AF_NETLINK - NETLINK_ROUTE
`

// NewNetworkBindInterface returns a new "network-bind" interface.
func NewNetworkBindInterface() interfaces.Interface {
	return &commonInterface{
		name: "network-bind",
		connectedPlugAppArmor: networkBindConnectedPlugAppArmor,
		connectedPlugSecComp:  networkBindConnectedPlugSecComp,
		reservedForOS:         true,
	}
}
