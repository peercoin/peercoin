#!/usr/bin/env python3
# Copyright (c) 2016-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Compatibility shim for historical siphash helper imports."""

from .crypto.siphash import siphash


def siphash256(k0, k1, data):
    return siphash(k0, k1, data)
