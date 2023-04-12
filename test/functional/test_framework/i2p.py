#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Dummy I2P SAM proxy server for testing."""

from base64 import b64encode

import socket
import threading
import logging

logger = logging.getLogger("TestFramework.i2p")

class I2PSAMServer():
    def __init__(self, addr='127.0.0.1', port=17656):
        self.addr = addr
        self.port = port
        self.socket = socket.socket(socket.AF_INET)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((addr, port))
        self.socket.listen()
        self.running = False
        self.thread = None
        self.conn = None

    def send(self, b):
        self.conn.sendall(b)

    def handle(self):
        def getline():
            line = bytearray()
            byte = self.conn.recv(1)
            while byte != b'\n':
                line.extend(byte)
                byte = self.conn.recv(1)
            return line.decode('utf8')

        def parseline():
            line = getline()
            words = line.split()
            words.reverse()
            ret = {}
            ret['cmd'] = words.pop()
            ret['subcmd'] = words.pop()
            while len(words):
                [k, v] = words.pop().split("=")
                ret[k] = v
            return ret

        def handleline():
            line = parseline()
            if line['cmd'] == "HELLO":
                self.send(b"HELLO REPLY RESULT=OK VERSION=3.1\n")
            elif line['cmd'] == "DEST":
                self.send(b"DEST REPLY PRIV=" + b64encode(bytearray(663)) + b"\n")
            elif line['cmd'] == "SESSION":
                self.send(b"SESSION STATUS RESULT=OK DESTINATION=" + b64encode(bytearray(663)) + b"\n")
            elif line['cmd'] == "STREAM":
                if line['subcmd'] == "ACCEPT":
                    self.send(b"STREAM STATUS RESULT=OK\n")
                elif line['subcmd'] == "CONNECT":
                    self.send(b"STREAM STATUS RESULT=OK\n")
                else:
                    assert False
            elif line['cmd'] == "NAMING":
                self.send(b"NAMING REPLY RESULT=OK VALUE=" + b64encode(bytearray(663)) + b"\n")
            else:
                raise Exception(f"Can not parse line: {line}")
            handleline()
        handleline()

    def run(self):
        while self.running:
            (self.conn, _) = self.socket.accept()
            if self.running:
                thread = threading.Thread(None, self.handle)
                thread.daemon = True
                thread.start()

    def start(self):
        assert not self.running
        self.running = True
        self.thread = threading.Thread(None, self.run)
        self.thread.daemon = True
        self.thread.start()

    def stop(self):
        self.running = False
        self.socket.close()
        self.thread.join()
