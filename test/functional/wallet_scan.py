#!/usr/bin/env python3
# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Ensure the wallet does not scan blocks prior to its birthday."""

import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal
)

class WalletScanTest(BitcoinTestFramework):
    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self):
        # Do not connect nodes yet
        self.setup_nodes()

    def run_test(self):
        self.log.debug("Create wallet and get address")
        miner = self.nodes[0]
        user = self.nodes[1]
        user.createwallet(wallet_name="user")
        user_wallet = user.get_wallet_rpc("user")
        addr = user_wallet.getnewaddress()
        now = time.time()

        self.log.info("Generate 10 blocks with 10-hour timestamp gaps")
        # 10-hour gaps ensure that no blocks overlap within `TIMESTAMP_WINDOW * 2`
        # Start 5 * 10-hour gaps ago
        timestamp = int(now) - (60 * 60 * 10 * 5)
        # Generate 5 blocks in the past and 5 in the future
        miner.setmocktime(timestamp)
        for _ in range(10):
            self.generatetoaddress(miner, 1, addr, sync_fun=self.no_op)
            timestamp += 60 * 60 * 10
            miner.setmocktime(timestamp)

        self.log.info("Initial blockchain sync the wallet's node")
        user.setmocktime(timestamp)
        assert user_wallet.getbalances()['mine']['immature'] == 0
        self.connect_nodes(0, 1)
        self.sync_all()

        # Only block rewards from height 6-10 should have been discovered
        assert_equal(user_wallet.getbalances()['mine']['immature'], 5 * 50)

if __name__ == '__main__':
    WalletScanTest().main()
