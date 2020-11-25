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

package lkenv

/**
 * Following structure has to be kept in sync with c structure defined by
 * include/lk/snappy-boot_v1.h
 * c headerfile is used by bootloader, this ensures sync of the environment
 * between snapd and bootloader

 * when this structure needs to be updated,
 * new version should be introduced instead together with c header file,
 * which is to be adopted by bootloader
 *
 * !!! Support for old version has to be maintained, as it is not guaranteed
 * all existing bootloader would adopt new version!
 */
type SnapBootSelect_v1 struct {
	/* Contains value BOOTSELECT_SIGNATURE defined above */
	Signature uint32
	/* snappy boot select version */
	Version uint32

	/* snap_mode, one of: 'empty', "try", "trying" */
	Snap_mode [SNAP_NAME_MAX_LEN]byte
	/* current core snap revision */
	Snap_core [SNAP_NAME_MAX_LEN]byte
	/* try core snap revision */
	Snap_try_core [SNAP_NAME_MAX_LEN]byte
	/* current kernel snap revision */
	Snap_kernel [SNAP_NAME_MAX_LEN]byte
	/* current kernel snap revision */
	Snap_try_kernel [SNAP_NAME_MAX_LEN]byte

	/* gadget_mode, one of: 'empty', "try", "trying" */
	Gadget_mode [SNAP_NAME_MAX_LEN]byte
	/* GADGET assets: current gadget assets revision */
	Snap_gadget [SNAP_NAME_MAX_LEN]byte
	/* GADGET assets: try gadget assets revision */
	Snap_try_gadget [SNAP_NAME_MAX_LEN]byte

	/**
	 * Reboot reason
	 * optional parameter to signal bootloader alternative reboot reasons
	 * e.g. recovery/factory-reset/boot asset update
	 */
	Reboot_reason [SNAP_NAME_MAX_LEN]byte

	/**
	 * Matrix for mapping of boot img partition to installed kernel snap revision
	 *
	 * First column represents boot image partition label (e.g. boot_a,boot_b )
	 *   value are static and should be populated at gadget built time
	 *   or latest at image build time. Values are not further altered at run time.
	 * Second column represents name currently installed kernel snap
	 *   e.g. pi2-kernel_123.snap
	 * initial value representing initial kernel snap revision
	 *   is populated at image build time by snapd
	 *
	 * There are two rows in the matrix, representing current and previous kernel revision
	 * following describes how this matrix should be modified at different stages:
	 *  - at image build time:
	 *    - extracted kernel snap revision name should be filled
	 *      into free slot (first row, second column)
	 *  - snapd:
	 *    - when new kernel snap revision is being installed, snapd cycles through
	 *      matrix to find unused 'boot slot' to be used for new kernel snap revision
	 *      from free slot, first column represents partition label to which kernel
	 *      snap boot image should be extracted. Second column is then populated with
	 *      kernel snap revision name.
	 *    - snap_mode, snap_try_kernel, snap_try_core behaves same way as with u-boot
	 *  - bootloader:
	 *    - bootloader reads snap_mode to determine if snap_kernel or snap_try_kernel is used
	 *      to get kernel snap revision name
	 *      kernel snap revision is then used to search matrix to determine
	 *      partition label to be used for current boot
	 *    - bootloader NEVER alters this matrix values
	 *
	 * [ <bootimg 1 part label> ] [ <kernel snap revision installed in this boot partition> ]
	 * [ <bootimg 2 part label> ] [ <kernel snap revision installed in this boot partition> ]
	 */
	Bootimg_matrix [SNAP_BOOTIMG_PART_NUM][2][SNAP_NAME_MAX_LEN]byte

	/**
	 * name of the boot image from kernel snap to be used for extraction
	 * when not defined or empty, default boot.img will be used
	 */
	Bootimg_file_name [SNAP_NAME_MAX_LEN]byte

	/**
	 * gadget assets: Matrix for mapping of gadget asset partitions
	 * Optional boot asset tracking, based on bootloader support
	 * Some boot chains support A/B boot assets for increased robustness
	 * example being A/B TrustExecutionEnvironment
	 * This matrix can be used to track current and try boot assets for
	 * robust updates
	 * Use of Gadget_asset_matrix matches use of Bootimg_matrix
	 *
	 * [ <boot assets 1 part label> ] [ <currently installed assets revision in this partition> ]
	 * [ <boot assets 2 part label> ] [ <currently installed assets revision in this partition> ]
	 */
	Gadget_asset_matrix [SNAP_BOOTIMG_PART_NUM][2][SNAP_NAME_MAX_LEN]byte

	/* unused placeholders for additional parameters in the future */
	Unused_key_01 [SNAP_NAME_MAX_LEN]byte
	Unused_key_02 [SNAP_NAME_MAX_LEN]byte
	Unused_key_03 [SNAP_NAME_MAX_LEN]byte
	Unused_key_04 [SNAP_NAME_MAX_LEN]byte
	Unused_key_05 [SNAP_NAME_MAX_LEN]byte
	Unused_key_06 [SNAP_NAME_MAX_LEN]byte
	Unused_key_07 [SNAP_NAME_MAX_LEN]byte
	Unused_key_08 [SNAP_NAME_MAX_LEN]byte
	Unused_key_09 [SNAP_NAME_MAX_LEN]byte
	Unused_key_10 [SNAP_NAME_MAX_LEN]byte
	Unused_key_11 [SNAP_NAME_MAX_LEN]byte
	Unused_key_12 [SNAP_NAME_MAX_LEN]byte
	Unused_key_13 [SNAP_NAME_MAX_LEN]byte
	Unused_key_14 [SNAP_NAME_MAX_LEN]byte
	Unused_key_15 [SNAP_NAME_MAX_LEN]byte
	Unused_key_16 [SNAP_NAME_MAX_LEN]byte
	Unused_key_17 [SNAP_NAME_MAX_LEN]byte
	Unused_key_18 [SNAP_NAME_MAX_LEN]byte
	Unused_key_19 [SNAP_NAME_MAX_LEN]byte
	Unused_key_20 [SNAP_NAME_MAX_LEN]byte

	/* unused array of 10 key value pairs */
	Key_value_pairs [10][2][SNAP_NAME_MAX_LEN]byte

	/* crc32 value for structure */
	Crc32 uint32
}
