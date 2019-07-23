#!/bin/bash

GRUB_EDITENV=grub-editenv
GRUBENV_FILE=/boot/grub/grubenv
case "$SPREAD_SYSTEM" in
    fedora-*|opensuse-*|amazon-*|centos-*)
        GRUB_EDITENV=grub2-editenv
        ;;
esac

bootenv() {
    if [ $# -eq 0 ]; then
        if command -v "$GRUB_EDITENV" >/dev/null; then
            "$GRUB_EDITENV" list
        elif [ -s "$GRUBENV_FILE" ]; then
            cat "$GRUBENV_FILE"
        else
            fw_printenv
        fi
    else
        if command -v "$GRUB_EDITENV" >/dev/null; then
            "$GRUB_EDITENV" list | grep "^$1"
        elif [ -s "$GRUBENV_FILE" ]; then
            cat "$GRUBENV_FILE" | grep "^$1"
        else
            fw_printenv "$1"
        fi | sed "s/^${1}=//"
    fi
}

# unset the given var from boot configuration
bootenv_unset() {
    local var="$1"

    if command -v "$GRUB_EDITENV" >/dev/null; then
        "$GRUB_EDITENV" /boot/grub/grubenv unset "$var"
    elif [ -s "$GRUBENV_FILE" ]; then
        sed -i "/^$var=/d" "$GRUBENV_FILE"
    else
        fw_setenv "$var"
    fi
}

get_boot_path() {
    if [ -f /boot/uboot/uboot.env ]; then
        echo "/boot/uboot/"
    elif [ -f /boot/grub/grubenv ]; then
        echo "/boot/grub/"
    else
        echo "Cannot determine boot path"
        ls -alR /boot
        exit 1
    fi
}
