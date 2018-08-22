// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2018 Canonical Ltd
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
	"github.com/snapcore/snapd/interfaces/udev"
	"github.com/snapcore/snapd/snap"
)

const adbSupportSummary = `allows access to connected USB devices for use with fastboot or adb`

const adbSupportBaseDeclarationSlots = `
  adb-support:
    allow-installation:
      slot-snap-type:
        - app
    deny-auto-connection: true
`

const adbSupportPermanentSlotUDev = ` 
# Concatenation of all adb udev rules.
# Do not edit this file, it will be overwritten on update.

# ACER
SUBSYSTEM=="usb", ATTR{idVendor}=="0502", MODE="0666"
# ALLWINNER
SUBSYSTEM=="usb", ATTR{idVendor}=="1f3a", MODE="0666"
# AMLOGIC
SUBSYSTEM=="usb", ATTR{idVendor}=="1b8e", MODE="0666"
# ANYDATA
SUBSYSTEM=="usb", ATTR{idVendor}=="16d5", MODE="0666"
# ARCHOS
SUBSYSTEM=="usb", ATTR{idVendor}=="0e79", MODE="0666"
# ASUS
SUBSYSTEM=="usb", ATTR{idVendor}=="0b05", MODE="0666"
# BQ
SUBSYSTEM=="usb", ATTR{idVendor}=="2a47", MODE="0666"
# BYD
SUBSYSTEM=="usb", ATTR{idVendor}=="1d91", MODE="0666"
# COMPAL
SUBSYSTEM=="usb", ATTR{idVendor}=="04b7", MODE="0666"
# COMPALCOMM
SUBSYSTEM=="usb", ATTR{idVendor}=="1219", MODE="0666"
# DELL
SUBSYSTEM=="usb", ATTR{idVendor}=="413c", MODE="0666"
# ECS
SUBSYSTEM=="usb", ATTR{idVendor}=="03fc", MODE="0666"
# EMERGING_TECH
SUBSYSTEM=="usb", ATTR{idVendor}=="297f", MODE="0666"
# EMERSON
SUBSYSTEM=="usb", ATTR{idVendor}=="2207", MODE="0666"
# FAIRPHONE
SUBSYSTEM=="usb", ATTR{idVendor}=="2ae5", MODE="0666"
# FOXCONN
SUBSYSTEM=="usb", ATTR{idVendor}=="0489", MODE="0666"
# FUJITSU
SUBSYSTEM=="usb", ATTR{idVendor}=="04c5", MODE="0666"
# FUNAI
SUBSYSTEM=="usb", ATTR{idVendor}=="0f1c", MODE="0666"
# GARMIN-ASUS
SUBSYSTEM=="usb", ATTR{idVendor}=="091e", MODE="0666"
# GIGABYTE
SUBSYSTEM=="usb", ATTR{idVendor}=="0414", MODE="0666"
# GIGASET
SUBSYSTEM=="usb", ATTR{idVendor}=="1e85", MODE="0666"
# GIONEE
SUBSYSTEM=="usb", ATTR{idVendor}=="271d", MODE="0666"
# GOOGLE
SUBSYSTEM=="usb", ATTR{idVendor}=="18d1", MODE="0666"
# HAIER
SUBSYSTEM=="usb", ATTR{idVendor}=="201e", MODE="0666"
# HARRIS
SUBSYSTEM=="usb", ATTR{idVendor}=="19a5", MODE="0666"
# HISENSE
SUBSYSTEM=="usb", ATTR{idVendor}=="109b", MODE="0666"
# HONEYWELL
SUBSYSTEM=="usb", ATTR{idVendor}=="0c2e", MODE="0666"
# HP
SUBSYSTEM=="usb", ATTR{idVendor}=="03f0", MODE="0666"
# HTC
SUBSYSTEM=="usb", ATTR{idVendor}=="0bb4", MODE="0666"
# HUAWEI
SUBSYSTEM=="usb", ATTR{idVendor}=="12d1", MODE="0666"
# INQ_MOBILE
SUBSYSTEM=="usb", ATTR{idVendor}=="2314", MODE="0666"
# INTEL
SUBSYSTEM=="usb", ATTR{idVendor}=="8087", MODE="0666"
# INTERMEC
SUBSYSTEM=="usb", ATTR{idVendor}=="067e", MODE="0666"
# IRIVER
SUBSYSTEM=="usb", ATTR{idVendor}=="2420", MODE="0666"
# K-TOUCH
SUBSYSTEM=="usb", ATTR{idVendor}=="24e3", MODE="0666"
# KT TECH
SUBSYSTEM=="usb", ATTR{idVendor}=="2116", MODE="0666"
# KOBO
SUBSYSTEM=="usb", ATTR{idVendor}=="2237", MODE="0666"
# KYOCERA
SUBSYSTEM=="usb", ATTR{idVendor}=="0482", MODE="0666"
# LAB126
SUBSYSTEM=="usb", ATTR{idVendor}=="1949", MODE="0666"
# LENOVO
SUBSYSTEM=="usb", ATTR{idVendor}=="17ef", MODE="0666"
# LENOVOMOBILE
SUBSYSTEM=="usb", ATTR{idVendor}=="2006", MODE="0666"
# LGE
SUBSYSTEM=="usb", ATTR{idVendor}=="1004", MODE="0666"
# LUMIGON
SUBSYSTEM=="usb", ATTR{idVendor}=="25e3", MODE="0666"
# MEIZU
SUBSYSTEM=="usb", ATTR{idVendor}=="2a45", MODE="0666"
# MOTOROLA
SUBSYSTEM=="usb", ATTR{idVendor}=="22b8", MODE="0666"
# MSI
SUBSYSTEM=="usb", ATTR{idVendor}=="0db0", MODE="0666"
# MTK
SUBSYSTEM=="usb", ATTR{idVendor}=="0e8d", MODE="0666"
# NEC
SUBSYSTEM=="usb", ATTR{idVendor}=="0409", MODE="0666"
# NOOK
SUBSYSTEM=="usb", ATTR{idVendor}=="2080", MODE="0666"
# NVIDIA
SUBSYSTEM=="usb", ATTR{idVendor}=="0955", MODE="0666"
# OPPO
SUBSYSTEM=="usb", ATTR{idVendor}=="22d9", MODE="0666"
# OTGV
SUBSYSTEM=="usb", ATTR{idVendor}=="2257", MODE="0666"
# OUYA
SUBSYSTEM=="usb", ATTR{idVendor}=="2836", MODE="0666"
# PANTECH
SUBSYSTEM=="usb", ATTR{idVendor}=="10a9", MODE="0666"
# PEGATRON
SUBSYSTEM=="usb", ATTR{idVendor}=="1d4d", MODE="0666"
# PHILPS
SUBSYSTEM=="usb", ATTR{idVendor}=="0471", MODE="0666"
# PMC-SIERRA
SUBSYSTEM=="usb", ATTR{idVendor}=="04da", MODE="0666"
# POSITIVO
SUBSYSTEM=="usb", ATTR{idVendor}=="1662", MODE="0666"
# PRESTIGIO
SUBSYSTEM=="usb", ATTR{idVendor}=="29e4", MODE="0666"
# QISDA
SUBSYSTEM=="usb", ATTR{idVendor}=="1d45", MODE="0666"
# Qualcomm
SUBSYSTEM=="usb", ATTR{idVendor}=="05c6", MODE="0666"
# QUANTA
SUBSYSTEM=="usb", ATTR{idVendor}=="0408", MODE="0666"
# ROCKCHIP
SUBSYSTEM=="usb", ATTR{idVendor}=="2207", MODE="0666"
# SAMSUNG
SUBSYSTEM=="usb", ATTR{idVendor}=="04e8", MODE="0666"
# SHARP
SUBSYSTEM=="usb", ATTR{idVendor}=="04dd", MODE="0666"
# SK TELESYS
SUBSYSTEM=="usb", ATTR{idVendor}=="1f53", MODE="0666"
# SMARTISAN
SUBSYSTEM=="usb", ATTR{idVendor}=="29a9", MODE="0666"
# SONY
SUBSYSTEM=="usb", ATTR{idVendor}=="054c", MODE="0666"
# SONY ERICSSON
SUBSYSTEM=="usb", ATTR{idVendor}=="0fce", MODE="0666"
# T_AND_A
SUBSYSTEM=="usb", ATTR{idVendor}=="1bbb", MODE="0666"
# TECHFAITH
SUBSYSTEM=="usb", ATTR{idVendor}=="1d09", MODE="0666"
# TELEEPOCH
SUBSYSTEM=="usb", ATTR{idVendor}=="2340", MODE="0666"
# TI
SUBSYSTEM=="usb", ATTR{idVendor}=="0451", MODE="0666"
# TOSHIBA
SUBSYSTEM=="usb", ATTR{idVendor}=="0930", MODE="0666"
# UNOWHY
SUBSYSTEM=="usb", ATTR{idVendor}=="2a49", MODE="0666"
# VIZIO
SUBSYSTEM=="usb", ATTR{idVendor}=="E040", MODE="0666"
# WACOM
SUBSYSTEM=="usb", ATTR{idVendor}=="0531", MODE="0666"
# XIAOMI
SUBSYSTEM=="usb", ATTR{idVendor}=="2717", MODE="0666"
# YOTADEVICES
SUBSYSTEM=="usb", ATTR{idVendor}=="2916", MODE="0666"
# YULONG_COOLPAD
SUBSYSTEM=="usb", ATTR{idVendor}=="1ebf", MODE="0666"
# ZTE
SUBSYSTEM=="usb", ATTR{idVendor}=="19d2", MODE="0666"
`

var adbSupportConnectedPlugUDev = []string{
	// ACER
	`SUBSYSTEM=="usb", ATTR{idVendor}=="0502"`,
	// ALLWINNER
	`SUBSYSTEM=="usb", ATTR{idVendor}=="1f3a"`,
	// AMLOGIC
	`SUBSYSTEM=="usb", ATTR{idVendor}=="1b8e"`,
	// ANYDATA
	`SUBSYSTEM=="usb", ATTR{idVendor}=="16d5"`,
	// ARCHOS
	`SUBSYSTEM=="usb", ATTR{idVendor}=="0e79"`,
	// ASUS
	`SUBSYSTEM=="usb", ATTR{idVendor}=="0b05"`,
	// BYD
	`SUBSYSTEM=="usb", ATTR{idVendor}=="1d91"`,
	// BQ
	`SUBSYSTEM=="usb", ATTR{idVendor}=="2a47"`,
	// COMPAL
	`SUBSYSTEM=="usb", ATTR{idVendor}=="04b7"`,
	// COMPALCOMM
	`SUBSYSTEM=="usb", ATTR{idVendor}=="1219"`,
	// DELL
	`SUBSYSTEM=="usb", ATTR{idVendor}=="413c"`,
	// ECS
	`SUBSYSTEM=="usb", ATTR{idVendor}=="03fc"`,
	// EMERGING_TECH
	`SUBSYSTEM=="usb", ATTR{idVendor}=="297f"`,
	// EMERSON
	`SUBSYSTEM=="usb", ATTR{idVendor}=="2207"`,
	// FAIRPHONE
	`SUBSYSTEM=="usb", ATTR{idVendor}=="2ae5"`,
	// FOXCONN
	`SUBSYSTEM=="usb", ATTR{idVendor}=="0489"`,
	// FUJITSU
	`SUBSYSTEM=="usb", ATTR{idVendor}=="04c5"`,
	// FUNAI
	`SUBSYSTEM=="usb", ATTR{idVendor}=="0f1c"`,
	// GARMIN-ASUS
	`SUBSYSTEM=="usb", ATTR{idVendor}=="091e"`,
	// GIGABYTE
	`SUBSYSTEM=="usb", ATTR{idVendor}=="0414"`,
	// GIGASET
	`SUBSYSTEM=="usb", ATTR{idVendor}=="1e85"`,
	// GIONEE
	`SUBSYSTEM=="usb", ATTR{idVendor}=="271d"`,
	// GOOGLE
	`SUBSYSTEM=="usb", ATTR{idVendor}=="18d1"`,
	// HAIER
	`SUBSYSTEM=="usb", ATTR{idVendor}=="201e"`,
	// HARRIS
	`SUBSYSTEM=="usb", ATTR{idVendor}=="19a5"`,
	// HISENSE
	`SUBSYSTEM=="usb", ATTR{idVendor}=="109b"`,
	// HONEYWELL
	`SUBSYSTEM=="usb", ATTR{idVendor}=="0c2e"`,
	// HP
	`SUBSYSTEM=="usb", ATTR{idVendor}=="03f0"`,
	// HTC
	`SUBSYSTEM=="usb", ATTR{idVendor}=="0bb4"`,
	// HUAWEI
	`SUBSYSTEM=="usb", ATTR{idVendor}=="12d1"`,
	// INQ_MOBILE
	`SUBSYSTEM=="usb", ATTR{idVendor}=="2314"`,
	// INTEL
	`SUBSYSTEM=="usb", ATTR{idVendor}=="8087"`,
	// INTERMEC
	`SUBSYSTEM=="usb", ATTR{idVendor}=="067e"`,
	// IRIVER
	`SUBSYSTEM=="usb", ATTR{idVendor}=="2420"`,
	// K-TOUCH
	`SUBSYSTEM=="usb", ATTR{idVendor}=="24e3"`,
	// KT TECH
	`SUBSYSTEM=="usb", ATTR{idVendor}=="2116"`,
	// KOBO
	`SUBSYSTEM=="usb", ATTR{idVendor}=="2237"`,
	// KYOCERA
	`SUBSYSTEM=="usb", ATTR{idVendor}=="0482"`,
	// LAB126
	`SUBSYSTEM=="usb", ATTR{idVendor}=="1949"`,
	// LENOVO
	`SUBSYSTEM=="usb", ATTR{idVendor}=="17ef"`,
	// LENOVOMOBILE
	`SUBSYSTEM=="usb", ATTR{idVendor}=="2006"`,
	// LGE
	`SUBSYSTEM=="usb", ATTR{idVendor}=="1004"`,
	// LUMIGON
	`SUBSYSTEM=="usb", ATTR{idVendor}=="25e3"`,
	// MEIZU
	`SUBSYSTEM=="usb", ATTR{idVendor}=="2a45"`,
	// MOTOROLA
	`SUBSYSTEM=="usb", ATTR{idVendor}=="22b8"`,
	// MSI
	`SUBSYSTEM=="usb", ATTR{idVendor}=="0db0"`,
	// MTK
	`SUBSYSTEM=="usb", ATTR{idVendor}=="0e8d"`,
	// NEC
	`SUBSYSTEM=="usb", ATTR{idVendor}=="0409"`,
	// NOOK
	`SUBSYSTEM=="usb", ATTR{idVendor}=="2080"`,
	// NVIDIA
	`SUBSYSTEM=="usb", ATTR{idVendor}=="0955"`,
	// OPPO
	`SUBSYSTEM=="usb", ATTR{idVendor}=="22d9"`,
	// OTGV
	`SUBSYSTEM=="usb", ATTR{idVendor}=="2257"`,
	// OUYA
	`SUBSYSTEM=="usb", ATTR{idVendor}=="2836"`,
	// PANTECH
	`SUBSYSTEM=="usb", ATTR{idVendor}=="10a9"`,
	// PEGATRON
	`SUBSYSTEM=="usb", ATTR{idVendor}=="1d4d"`,
	// PHILPS
	`SUBSYSTEM=="usb", ATTR{idVendor}=="0471"`,
	// PMC-SIERRA
	`SUBSYSTEM=="usb", ATTR{idVendor}=="04da"`,
	// POSITIVO
	`SUBSYSTEM=="usb", ATTR{idVendor}=="1662"`,
	// PRESTIGIO
	`SUBSYSTEM=="usb", ATTR{idVendor}=="29e4"`,
	// QISDA
	`SUBSYSTEM=="usb", ATTR{idVendor}=="1d45"`,
	// Qualcomm
	`SUBSYSTEM=="usb", ATTR{idVendor}=="05c6"`,
	// QUANTA
	`SUBSYSTEM=="usb", ATTR{idVendor}=="0408"`,
	// ROCKCHIP
	`SUBSYSTEM=="usb", ATTR{idVendor}=="2207"`,
	// SAMSUNG
	`SUBSYSTEM=="usb", ATTR{idVendor}=="04e8"`,
	// SHARP
	`SUBSYSTEM=="usb", ATTR{idVendor}=="04dd"`,
	// SK TELESYS
	`SUBSYSTEM=="usb", ATTR{idVendor}=="1f53"`,
	// SMARTISAN
	`SUBSYSTEM=="usb", ATTR{idVendor}=="29a9"`,
	// SONY
	`SUBSYSTEM=="usb", ATTR{idVendor}=="054c"`,
	// SONY ERICSSON
	`SUBSYSTEM=="usb", ATTR{idVendor}=="0fce"`,
	// T_AND_A
	`SUBSYSTEM=="usb", ATTR{idVendor}=="1bbb"`,
	// TECHFAITH
	`SUBSYSTEM=="usb", ATTR{idVendor}=="1d09"`,
	// TELEEPOCH
	`SUBSYSTEM=="usb", ATTR{idVendor}=="2340"`,
	// TI
	`SUBSYSTEM=="usb", ATTR{idVendor}=="0451"`,
	// TOSHIBA
	`SUBSYSTEM=="usb", ATTR{idVendor}=="0930"`,
	// UNOWHY
	`SUBSYSTEM=="usb", ATTR{idVendor}=="2a49"`,
	// VIZIO
	`SUBSYSTEM=="usb", ATTR{idVendor}=="E040"`,
	// WACOM
	`SUBSYSTEM=="usb", ATTR{idVendor}=="0531"`,
	// XIAOMI
	`SUBSYSTEM=="usb", ATTR{idVendor}=="2717"`,
	// YOTADEVICES
	`SUBSYSTEM=="usb", ATTR{idVendor}=="2916"`,
	// YULONG_COOLPAD
	`SUBSYSTEM=="usb", ATTR{idVendor}=="1ebf"`,
	// ZTE
	`SUBSYSTEM=="usb", ATTR{idVendor}=="19d2"`,
}

var adbSupportConnectedPlugAppArmor = `
# Description: Allow access to all adb USB devices
# Allow all usb devices here and rely on the device cgroup for mediation
/dev/bus/usb/[0-9][0-9][0-9]/[0-9][0-9][0-9] rw,

# Allow access to udev meta-data about character devices with major number 189
# as per https://www.kernel.org/doc/Documentation/admin-guide/devices.txt
# those describe "USB serial converters - alternate devices". This is what I
# get after plugging in a derivative of Android to my system.
/run/udev/data/c189:* r,
`

type adbSupportInterface struct {
	commonInterface
}

func (iface *adbSupportInterface) UDevPermanentSlot(spec *udev.Specification, slot *snap.SlotInfo) error {
	spec.AddSnippet(adbSupportPermanentSlotUDev)
	return nil
}

func init() {
	registerIface(&adbSupportInterface{commonInterface{
		name:                  "adb-support",
		summary:               adbSupportSummary,
		baseDeclarationSlots:  adbSupportBaseDeclarationSlots,
		connectedPlugUDev:     adbSupportConnectedPlugUDev,
		connectedPlugAppArmor: adbSupportConnectedPlugAppArmor,
		reservedForOS:         true,
	}})
}
