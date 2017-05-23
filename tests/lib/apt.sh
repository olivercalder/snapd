#!/bin/bash

. $TESTSLIB/pkgdb.sh

install_build_snapd(){
    if [ "$SRU_VALIDATION" = "1" ]; then
        apt install -y snapd
        cp /etc/apt/sources.list sources.list.back
        echo "deb http://archive.ubuntu.com/ubuntu/ $(lsb_release -c -s)-proposed restricted main multiverse universe" | tee /etc/apt/sources.list -a
        apt update
        apt install -y --only-upgrade snapd
        mv sources.list.back /etc/apt/sources.list
        apt update
        if [ "$SPREAD_REBOOT" = 0 ]; then
            REBOOT
        fi
    else
        packages="${GOPATH}/snapd_*.deb"
        distro_install_local_package $packages
    fi
}
