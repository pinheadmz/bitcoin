#!/usr/bin/env python3
# Copyright (c) 2020-2021 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test block-relay-only anchors functionality"""

import hashlib
import os

from test_framework.p2p import P2PInterface, P2P_SERVICES
from test_framework.socks5 import Socks5Configuration, Socks5Server
from test_framework.messages import CAddress
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import check_node_connections

INBOUND_CONNECTIONS = 5
BLOCK_RELAY_CONNECTIONS = 2


class AnchorsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.disable_autoconnect = False

    def run_test(self):
        node_anchors_path = os.path.join(
            self.nodes[0].datadir, "regtest", "anchors.dat"
        )

        self.log.info("When node starts, check if anchors.dat doesn't exist")
        assert not os.path.exists(node_anchors_path)

        self.log.info(f"Add {BLOCK_RELAY_CONNECTIONS} block-relay-only connections to node")
        for i in range(BLOCK_RELAY_CONNECTIONS):
            self.log.debug(f"block-relay-only: {i}")
            self.nodes[0].add_outbound_p2p_connection(
                P2PInterface(), p2p_idx=i, connection_type="block-relay-only"
            )

        self.log.info(f"Add {INBOUND_CONNECTIONS} inbound connections to node")
        for i in range(INBOUND_CONNECTIONS):
            self.log.debug(f"inbound: {i}")
            self.nodes[0].add_p2p_connection(P2PInterface())

        self.log.info("Check node connections")
        check_node_connections(node=self.nodes[0], num_in=5, num_out=2)

        # 127.0.0.1
        ip = "7f000001"

        # Since the ip is always 127.0.0.1 for this case,
        # we store only the port to identify the peers
        block_relay_nodes_port = []
        inbound_nodes_port = []
        for p in self.nodes[0].getpeerinfo():
            addr_split = p["addr"].split(":")
            if p["connection_type"] == "block-relay-only":
                block_relay_nodes_port.append(hex(int(addr_split[1]))[2:])
            else:
                inbound_nodes_port.append(hex(int(addr_split[1]))[2:])

        self.log.info("Stop node 0")
        self.stop_node(0)

        # It should contain only the block-relay-only addresses
        self.log.info("Check the addresses in anchors.dat")

        with open(node_anchors_path, "rb") as file_handler:
            anchors = file_handler.read().hex()

        for port in block_relay_nodes_port:
            ip_port = ip + port
            assert ip_port in anchors
        for port in inbound_nodes_port:
            ip_port = ip + port
            assert ip_port not in anchors

        self.log.info("Start node")
        self.start_node(0)

        self.log.info("When node starts, check if anchors.dat doesn't exist anymore")
        assert not os.path.exists(node_anchors_path)

        self.log.info("Ensure addrv2 support")
        # Use proxies to catch outbound connections to networks with 256-bit addresses
        onion_conf = Socks5Configuration()
        onion_conf.auth = True
        onion_conf.unauth = True
        onion_conf.addr = ('127.0.0.1', 10000)
        onion_proxy = Socks5Server(onion_conf)
        onion_proxy.start()
        self.restart_node(0, extra_args=[f"-onion={onion_conf.addr[0]}:{onion_conf.addr[1]}"])

        self.log.info(f"Add 256-bit-address block-relay-only connections to node")
        ONION_ADDR = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
        self.nodes[0].addconnection(ONION_ADDR, 'block-relay-only')

        self.log.info("Check peer info")
        peer_info = self.nodes[0].getpeerinfo()
        assert len(peer_info) == 1
        assert peer_info[0]["network"] == "onion"
        assert peer_info[0]["connection_type"] == "block-relay-only"

        self.log.info("Stop node 0")
        self.stop_node(0)

        self.log.info("Check for addrv2 addresses in anchors.dat")
        caddr = CAddress()
        caddr.net = CAddress.NET_TORV3
        [caddr.ip, port_str] = ONION_ADDR.split(":")
        caddr.port = int(port_str)
        # TorV3 addrv2 serialization:
        # time(4) | services(1) | networkID(1) | address length(1) | address(32)
        expected_pubkey = caddr.serialize_v2()[7:39].hex()

        # position of services byte of first addr in anchors.dat
        # network magic, vector length, version, nTime
        services_index = 4 + 1 + 4 + 4
        data = bytes()
        with open(node_anchors_path, "rb") as file_handler:
            data = file_handler.read()
            assert data[services_index] == 0x00 # services == NONE
            anchors2 = data.hex()
            assert expected_pubkey in anchors2

        with open(node_anchors_path, "wb") as file_handler:
            # Cheat: modify service flags for this address
            # even though we never connected to it
            new_data = bytearray(data)[:-32]
            new_data[services_index] = P2P_SERVICES
            new_data_hash = hashlib.sha256(hashlib.sha256(new_data).digest()).digest()
            file_handler.write(new_data + new_data_hash)

        self.log.info("Restarting node attempts to reconnect to anchors")
        with self.nodes[0].assert_debug_log([f"Trying to make an anchor connection to {ONION_ADDR}"]):
            self.start_node(0, extra_args=[f"-onion={onion_conf.addr[0]}:{onion_conf.addr[1]}"])

if __name__ == "__main__":
    AnchorsTest().main()
