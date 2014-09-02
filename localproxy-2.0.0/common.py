#! /usr/bin/env python
# coding=utf-8

import os, sys

def we_are_frozen():
    """Returns whether we are frozen via py2exe.
    This will affect how we find out where we are located."""

    return hasattr(sys, "frozen")

def module_path():
    """ This will get us the program's directory,
    even if we are frozen using py2exe"""

    if we_are_frozen():
        return os.path.dirname(sys.executable)
    return os.path.dirname(__file__)

dir = module_path()

VERSION = "2.0.0"

DEF_LISTEN_PORT = 8001
DEF_LOCAL_PROXY = ''
DEF_FETCH_SERVER = ''
DEF_CONF_FILE = os.path.join(dir, 'proxy.conf')
DEF_CERT_FILE = os.path.join(dir, 'ssl/LocalProxyServer.cert')
DEF_KEY_FILE  = os.path.join(dir, 'ssl/LocalProxyServer.key')

class GAppProxyError(Exception):
    def __init__(self, reason):
        self.reason = reason

    def __str__(self):
        return '<GAppProxy Error: %s>' % self.reason
