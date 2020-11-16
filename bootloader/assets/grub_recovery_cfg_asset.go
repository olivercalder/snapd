// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2020 Canonical Ltd
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

package assets

// Code generated from ./data/grub-recovery.cfg DO NOT EDIT

func init() {
	registerInternal("grub-recovery.cfg", []byte{
		0x23, 0x20, 0x53, 0x6e, 0x61, 0x70, 0x64, 0x2d, 0x42, 0x6f, 0x6f, 0x74, 0x2d, 0x43, 0x6f, 0x6e,
		0x66, 0x69, 0x67, 0x2d, 0x45, 0x64, 0x69, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x31, 0x0a, 0x0a,
		0x73, 0x65, 0x74, 0x20, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x3d, 0x30, 0x0a, 0x73, 0x65,
		0x74, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x3d, 0x33, 0x0a, 0x73, 0x65, 0x74, 0x20,
		0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x5f, 0x73, 0x74, 0x79, 0x6c, 0x65, 0x3d, 0x68, 0x69,
		0x64, 0x64, 0x65, 0x6e, 0x0a, 0x0a, 0x69, 0x66, 0x20, 0x5b, 0x20, 0x2d, 0x65, 0x20, 0x2f, 0x45,
		0x46, 0x49, 0x2f, 0x75, 0x62, 0x75, 0x6e, 0x74, 0x75, 0x2f, 0x67, 0x72, 0x75, 0x62, 0x65, 0x6e,
		0x76, 0x20, 0x5d, 0x3b, 0x20, 0x74, 0x68, 0x65, 0x6e, 0x0a, 0x20, 0x20, 0x20, 0x6c, 0x6f, 0x61,
		0x64, 0x5f, 0x65, 0x6e, 0x76, 0x20, 0x2d, 0x2d, 0x66, 0x69, 0x6c, 0x65, 0x20, 0x2f, 0x45, 0x46,
		0x49, 0x2f, 0x75, 0x62, 0x75, 0x6e, 0x74, 0x75, 0x2f, 0x67, 0x72, 0x75, 0x62, 0x65, 0x6e, 0x76,
		0x20, 0x73, 0x6e, 0x61, 0x70, 0x64, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x5f,
		0x6d, 0x6f, 0x64, 0x65, 0x20, 0x73, 0x6e, 0x61, 0x70, 0x64, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76,
		0x65, 0x72, 0x79, 0x5f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x0a, 0x66, 0x69, 0x0a, 0x0a, 0x23,
		0x20, 0x73, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x72, 0x64, 0x20, 0x63, 0x6d, 0x64, 0x6c, 0x69, 0x6e,
		0x65, 0x20, 0x70, 0x61, 0x72, 0x61, 0x6d, 0x73, 0x0a, 0x73, 0x65, 0x74, 0x20, 0x73, 0x6e, 0x61,
		0x70, 0x64, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x69, 0x63, 0x5f, 0x63, 0x6d, 0x64, 0x6c, 0x69, 0x6e,
		0x65, 0x5f, 0x61, 0x72, 0x67, 0x73, 0x3d, 0x27, 0x63, 0x6f, 0x6e, 0x73, 0x6f, 0x6c, 0x65, 0x3d,
		0x74, 0x74, 0x79, 0x53, 0x30, 0x20, 0x63, 0x6f, 0x6e, 0x73, 0x6f, 0x6c, 0x65, 0x3d, 0x74, 0x74,
		0x79, 0x31, 0x20, 0x70, 0x61, 0x6e, 0x69, 0x63, 0x3d, 0x2d, 0x31, 0x27, 0x0a, 0x0a, 0x23, 0x20,
		0x69, 0x66, 0x20, 0x6e, 0x6f, 0x20, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x20, 0x62, 0x6f,
		0x6f, 0x74, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x20, 0x73, 0x65, 0x74, 0x2c, 0x20, 0x70, 0x69, 0x63,
		0x6b, 0x20, 0x6f, 0x6e, 0x65, 0x0a, 0x69, 0x66, 0x20, 0x5b, 0x20, 0x2d, 0x7a, 0x20, 0x22, 0x24,
		0x73, 0x6e, 0x61, 0x70, 0x64, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6d,
		0x6f, 0x64, 0x65, 0x22, 0x20, 0x5d, 0x3b, 0x20, 0x74, 0x68, 0x65, 0x6e, 0x0a, 0x20, 0x20, 0x20,
		0x20, 0x73, 0x65, 0x74, 0x20, 0x73, 0x6e, 0x61, 0x70, 0x64, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76,
		0x65, 0x72, 0x79, 0x5f, 0x6d, 0x6f, 0x64, 0x65, 0x3d, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x6c, 0x6c,
		0x0a, 0x66, 0x69, 0x0a, 0x0a, 0x69, 0x66, 0x20, 0x5b, 0x20, 0x22, 0x24, 0x73, 0x6e, 0x61, 0x70,
		0x64, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6d, 0x6f, 0x64, 0x65, 0x22,
		0x20, 0x3d, 0x20, 0x22, 0x72, 0x75, 0x6e, 0x22, 0x20, 0x5d, 0x3b, 0x20, 0x74, 0x68, 0x65, 0x6e,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x3d, 0x22, 0x72, 0x75,
		0x6e, 0x22, 0x0a, 0x65, 0x6c, 0x69, 0x66, 0x20, 0x5b, 0x20, 0x2d, 0x6e, 0x20, 0x22, 0x24, 0x73,
		0x6e, 0x61, 0x70, 0x64, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x73, 0x79,
		0x73, 0x74, 0x65, 0x6d, 0x22, 0x20, 0x5d, 0x3b, 0x20, 0x74, 0x68, 0x65, 0x6e, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x3d, 0x24, 0x73, 0x6e, 0x61, 0x70, 0x64,
		0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6d, 0x6f, 0x64, 0x65, 0x2d, 0x24,
		0x73, 0x6e, 0x61, 0x70, 0x64, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x73,
		0x79, 0x73, 0x74, 0x65, 0x6d, 0x0a, 0x66, 0x69, 0x0a, 0x0a, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68,
		0x20, 0x2d, 0x2d, 0x6e, 0x6f, 0x2d, 0x66, 0x6c, 0x6f, 0x70, 0x70, 0x79, 0x20, 0x2d, 0x2d, 0x73,
		0x65, 0x74, 0x3d, 0x62, 0x6f, 0x6f, 0x74, 0x5f, 0x66, 0x73, 0x20, 0x2d, 0x2d, 0x6c, 0x61, 0x62,
		0x65, 0x6c, 0x20, 0x75, 0x62, 0x75, 0x6e, 0x74, 0x75, 0x2d, 0x62, 0x6f, 0x6f, 0x74, 0x0a, 0x0a,
		0x69, 0x66, 0x20, 0x5b, 0x20, 0x2d, 0x6e, 0x20, 0x22, 0x24, 0x62, 0x6f, 0x6f, 0x74, 0x5f, 0x66,
		0x73, 0x22, 0x20, 0x5d, 0x3b, 0x20, 0x74, 0x68, 0x65, 0x6e, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x6d,
		0x65, 0x6e, 0x75, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x22, 0x43, 0x6f, 0x6e, 0x74, 0x69, 0x6e,
		0x75, 0x65, 0x20, 0x74, 0x6f, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x22, 0x20,
		0x2d, 0x2d, 0x68, 0x6f, 0x74, 0x6b, 0x65, 0x79, 0x3d, 0x6e, 0x20, 0x2d, 0x2d, 0x69, 0x64, 0x3d,
		0x72, 0x75, 0x6e, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x63, 0x68,
		0x61, 0x69, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x65, 0x72, 0x20, 0x28, 0x24, 0x62, 0x6f, 0x6f, 0x74,
		0x5f, 0x66, 0x73, 0x29, 0x2f, 0x45, 0x46, 0x49, 0x2f, 0x62, 0x6f, 0x6f, 0x74, 0x2f, 0x67, 0x72,
		0x75, 0x62, 0x78, 0x36, 0x34, 0x2e, 0x65, 0x66, 0x69, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x7d, 0x0a,
		0x66, 0x69, 0x0a, 0x0a, 0x23, 0x20, 0x67, 0x6c, 0x6f, 0x62, 0x62, 0x69, 0x6e, 0x67, 0x20, 0x69,
		0x6e, 0x20, 0x67, 0x72, 0x75, 0x62, 0x20, 0x64, 0x6f, 0x65, 0x73, 0x20, 0x6e, 0x6f, 0x74, 0x20,
		0x73, 0x6f, 0x72, 0x74, 0x0a, 0x66, 0x6f, 0x72, 0x20, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x20, 0x69,
		0x6e, 0x20, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2f, 0x2a, 0x3b, 0x20, 0x64, 0x6f,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x72, 0x65, 0x67, 0x65, 0x78, 0x70, 0x20, 0x2d, 0x2d, 0x73, 0x65,
		0x74, 0x20, 0x31, 0x3a, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x20, 0x22, 0x2f, 0x28, 0x5b, 0x30, 0x2d,
		0x39, 0x5d, 0x2a, 0x29, 0x5c, 0x24, 0x22, 0x20, 0x22, 0x24, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x22,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x69, 0x66, 0x20, 0x5b, 0x20, 0x2d, 0x7a, 0x20, 0x22, 0x24, 0x6c,
		0x61, 0x62, 0x65, 0x6c, 0x22, 0x20, 0x5d, 0x3b, 0x20, 0x74, 0x68, 0x65, 0x6e, 0x0a, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x69, 0x6e, 0x75, 0x65, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x66, 0x69, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x23, 0x20, 0x79, 0x65, 0x73, 0x2c,
		0x20, 0x79, 0x6f, 0x75, 0x20, 0x6e, 0x65, 0x65, 0x64, 0x20, 0x74, 0x6f, 0x20, 0x62, 0x61, 0x63,
		0x6b, 0x73, 0x6c, 0x61, 0x73, 0x68, 0x20, 0x74, 0x68, 0x61, 0x74, 0x20, 0x6c, 0x65, 0x73, 0x73,
		0x2d, 0x74, 0x68, 0x61, 0x6e, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x69, 0x66, 0x20, 0x5b, 0x20, 0x2d,
		0x7a, 0x20, 0x22, 0x24, 0x62, 0x65, 0x73, 0x74, 0x22, 0x20, 0x2d, 0x6f, 0x20, 0x22, 0x24, 0x6c,
		0x61, 0x62, 0x65, 0x6c, 0x22, 0x20, 0x5c, 0x3c, 0x20, 0x22, 0x24, 0x62, 0x65, 0x73, 0x74, 0x22,
		0x20, 0x5d, 0x3b, 0x20, 0x74, 0x68, 0x65, 0x6e, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x73, 0x65, 0x74, 0x20, 0x62, 0x65, 0x73, 0x74, 0x3d, 0x22, 0x24, 0x6c, 0x61, 0x62, 0x65,
		0x6c, 0x22, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x66, 0x69, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x23, 0x20,
		0x69, 0x66, 0x20, 0x67, 0x72, 0x75, 0x62, 0x65, 0x6e, 0x76, 0x20, 0x64, 0x69, 0x64, 0x20, 0x6e,
		0x6f, 0x74, 0x20, 0x70, 0x69, 0x63, 0x6b, 0x20, 0x6d, 0x6f, 0x64, 0x65, 0x2d, 0x73, 0x79, 0x73,
		0x74, 0x65, 0x6d, 0x2c, 0x20, 0x75, 0x73, 0x65, 0x20, 0x62, 0x65, 0x73, 0x74, 0x20, 0x6f, 0x6e,
		0x65, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x69, 0x66, 0x20, 0x5b, 0x20, 0x2d, 0x7a, 0x20, 0x22, 0x24,
		0x73, 0x6e, 0x61, 0x70, 0x64, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x73,
		0x79, 0x73, 0x74, 0x65, 0x6d, 0x22, 0x20, 0x5d, 0x3b, 0x20, 0x74, 0x68, 0x65, 0x6e, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x64, 0x65, 0x66, 0x61, 0x75, 0x6c, 0x74, 0x3d, 0x24,
		0x73, 0x6e, 0x61, 0x70, 0x64, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6d,
		0x6f, 0x64, 0x65, 0x2d, 0x24, 0x62, 0x65, 0x73, 0x74, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x66, 0x69,
		0x0a, 0x20, 0x20, 0x20, 0x20, 0x73, 0x65, 0x74, 0x20, 0x73, 0x6e, 0x61, 0x70, 0x64, 0x5f, 0x72,
		0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x3d, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x6c, 0x6f, 0x61, 0x64, 0x5f, 0x65, 0x6e, 0x76, 0x20, 0x2d, 0x2d, 0x66,
		0x69, 0x6c, 0x65, 0x20, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2f, 0x24, 0x6c, 0x61,
		0x62, 0x65, 0x6c, 0x2f, 0x67, 0x72, 0x75, 0x62, 0x65, 0x6e, 0x76, 0x20, 0x73, 0x6e, 0x61, 0x70,
		0x64, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6b, 0x65, 0x72, 0x6e, 0x65,
		0x6c, 0x20, 0x73, 0x6e, 0x61, 0x70, 0x64, 0x5f, 0x65, 0x78, 0x74, 0x72, 0x61, 0x5f, 0x63, 0x6d,
		0x64, 0x6c, 0x69, 0x6e, 0x65, 0x5f, 0x61, 0x72, 0x67, 0x73, 0x0a, 0x0a, 0x20, 0x20, 0x20, 0x20,
		0x23, 0x20, 0x57, 0x65, 0x20, 0x63, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x22, 0x73, 0x6f, 0x75, 0x72,
		0x63, 0x65, 0x20, 0x2f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x73, 0x2f, 0x24, 0x73, 0x6e, 0x61,
		0x70, 0x64, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x73, 0x79, 0x73, 0x74,
		0x65, 0x6d, 0x2f, 0x67, 0x72, 0x75, 0x62, 0x2e, 0x63, 0x66, 0x67, 0x22, 0x20, 0x68, 0x65, 0x72,
		0x65, 0x20, 0x61, 0x73, 0x20, 0x77, 0x65, 0x6c, 0x6c, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x6d, 0x65,
		0x6e, 0x75, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x22, 0x52, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72,
		0x20, 0x75, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x24, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x22, 0x20, 0x2d,
		0x2d, 0x68, 0x6f, 0x74, 0x6b, 0x65, 0x79, 0x3d, 0x72, 0x20, 0x2d, 0x2d, 0x69, 0x64, 0x3d, 0x72,
		0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x2d, 0x24, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x20, 0x24, 0x73,
		0x6e, 0x61, 0x70, 0x64, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6b, 0x65,
		0x72, 0x6e, 0x65, 0x6c, 0x20, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x24, 0x6c, 0x61,
		0x62, 0x65, 0x6c, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x6c, 0x6f,
		0x6f, 0x70, 0x62, 0x61, 0x63, 0x6b, 0x20, 0x6c, 0x6f, 0x6f, 0x70, 0x20, 0x24, 0x32, 0x0a, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x6c, 0x6f, 0x61, 0x64,
		0x65, 0x72, 0x20, 0x28, 0x6c, 0x6f, 0x6f, 0x70, 0x29, 0x2f, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c,
		0x2e, 0x65, 0x66, 0x69, 0x20, 0x73, 0x6e, 0x61, 0x70, 0x64, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76,
		0x65, 0x72, 0x79, 0x5f, 0x6d, 0x6f, 0x64, 0x65, 0x3d, 0x24, 0x33, 0x20, 0x73, 0x6e, 0x61, 0x70,
		0x64, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x73, 0x79, 0x73, 0x74, 0x65,
		0x6d, 0x3d, 0x24, 0x34, 0x20, 0x24, 0x73, 0x6e, 0x61, 0x70, 0x64, 0x5f, 0x73, 0x74, 0x61, 0x74,
		0x69, 0x63, 0x5f, 0x63, 0x6d, 0x64, 0x6c, 0x69, 0x6e, 0x65, 0x5f, 0x61, 0x72, 0x67, 0x73, 0x20,
		0x24, 0x73, 0x6e, 0x61, 0x70, 0x64, 0x5f, 0x65, 0x78, 0x74, 0x72, 0x61, 0x5f, 0x63, 0x6d, 0x64,
		0x6c, 0x69, 0x6e, 0x65, 0x5f, 0x61, 0x72, 0x67, 0x73, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x7d, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x6d, 0x65, 0x6e, 0x75, 0x65, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x22, 0x49,
		0x6e, 0x73, 0x74, 0x61, 0x6c, 0x6c, 0x20, 0x75, 0x73, 0x69, 0x6e, 0x67, 0x20, 0x24, 0x6c, 0x61,
		0x62, 0x65, 0x6c, 0x22, 0x20, 0x2d, 0x2d, 0x68, 0x6f, 0x74, 0x6b, 0x65, 0x79, 0x3d, 0x69, 0x20,
		0x2d, 0x2d, 0x69, 0x64, 0x3d, 0x69, 0x6e, 0x73, 0x74, 0x61, 0x6c, 0x6c, 0x2d, 0x24, 0x6c, 0x61,
		0x62, 0x65, 0x6c, 0x20, 0x24, 0x73, 0x6e, 0x61, 0x70, 0x64, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76,
		0x65, 0x72, 0x79, 0x5f, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x20, 0x69, 0x6e, 0x73, 0x74, 0x61,
		0x6c, 0x6c, 0x20, 0x24, 0x6c, 0x61, 0x62, 0x65, 0x6c, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20,
		0x20, 0x20, 0x20, 0x20, 0x6c, 0x6f, 0x6f, 0x70, 0x62, 0x61, 0x63, 0x6b, 0x20, 0x6c, 0x6f, 0x6f,
		0x70, 0x20, 0x24, 0x32, 0x0a, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x63, 0x68, 0x61,
		0x69, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x65, 0x72, 0x20, 0x28, 0x6c, 0x6f, 0x6f, 0x70, 0x29, 0x2f,
		0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x2e, 0x65, 0x66, 0x69, 0x20, 0x73, 0x6e, 0x61, 0x70, 0x64,
		0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x5f, 0x6d, 0x6f, 0x64, 0x65, 0x3d, 0x24,
		0x33, 0x20, 0x73, 0x6e, 0x61, 0x70, 0x64, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79,
		0x5f, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x3d, 0x24, 0x34, 0x20, 0x24, 0x73, 0x6e, 0x61, 0x70,
		0x64, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x69, 0x63, 0x5f, 0x63, 0x6d, 0x64, 0x6c, 0x69, 0x6e, 0x65,
		0x5f, 0x61, 0x72, 0x67, 0x73, 0x20, 0x24, 0x73, 0x6e, 0x61, 0x70, 0x64, 0x5f, 0x65, 0x78, 0x74,
		0x72, 0x61, 0x5f, 0x63, 0x6d, 0x64, 0x6c, 0x69, 0x6e, 0x65, 0x5f, 0x61, 0x72, 0x67, 0x73, 0x0a,
		0x20, 0x20, 0x20, 0x20, 0x7d, 0x0a, 0x64, 0x6f, 0x6e, 0x65, 0x0a, 0x0a, 0x6d, 0x65, 0x6e, 0x75,
		0x65, 0x6e, 0x74, 0x72, 0x79, 0x20, 0x27, 0x55, 0x45, 0x46, 0x49, 0x20, 0x46, 0x69, 0x72, 0x6d,
		0x77, 0x61, 0x72, 0x65, 0x20, 0x53, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x73, 0x27, 0x20, 0x2d,
		0x2d, 0x68, 0x6f, 0x74, 0x6b, 0x65, 0x79, 0x3d, 0x66, 0x20, 0x27, 0x75, 0x65, 0x66, 0x69, 0x2d,
		0x66, 0x69, 0x72, 0x6d, 0x77, 0x61, 0x72, 0x65, 0x27, 0x20, 0x7b, 0x0a, 0x20, 0x20, 0x20, 0x20,
		0x66, 0x77, 0x73, 0x65, 0x74, 0x75, 0x70, 0x0a, 0x7d, 0x0a,
	})
}
