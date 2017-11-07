#!/usr/bin/env python

import dbus
import os
import sys

def _get_obj():
    return dbus.SystemBus().get_object("com.ubuntu.connectivity1.NetworkingStatus", "/com/ubuntu/connectivity1/NetworkingStatus")

def get_version():
    obj = _get_obj()
    print(obj.GetVersion(dbus_interface="com.ubuntu.connectivity1.NetworkingStatus"))

def get_state():
    obj = _get_obj()
    print(obj.GetState(dbus_interface="com.ubuntu.connectivity1.NetworkingStatus"))

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "GetState":
        sys.exit(get_state())
    else:
        sys.exit(get_version())
