#!/usr/bin/env python3
# Copyright (c) 2014-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test running bitcoind with the -rpcbind and -rpcallowip options."""

import os
import tempfile
from pathlib import Path

from test_framework.netutil import NETWORK_ERRORS, all_interfaces, addr_to_hex, get_bind_addrs, test_ipv6_local, test_unix_socket
from test_framework.test_framework import BitcoinTestFramework, SkipTest
from test_framework.test_node import ErrorMatch
from test_framework.util import assert_equal, rpc_port

class RPCBindTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.bind_to_localhost_only = False
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_platform_not_posix()
        self.skip_if_no_lsof_on_nonlinux()

    def setup_network(self):
        self.add_nodes(self.num_nodes, None)

    def add_options(self, parser):
        parser.add_argument("--ipv4", action='store_true', dest="run_ipv4", help="Run ipv4 tests only", default=False)
        parser.add_argument("--ipv6", action='store_true', dest="run_ipv6", help="Run ipv6 tests only", default=False)
        parser.add_argument("--nonloopback", action='store_true', dest="run_nonloopback", help="Run non-loopback tests only", default=False)

    def run_bind_test(self, allow_ips, connect_to, addresses, expected):
        '''
        Start a node with requested rpcallowip and rpcbind parameters,
        then try to connect, and check if the set of bound addresses
        matches the expected set.
        '''
        self.log.info(f"Bind test for {str(addresses)} with -rpcallowip={str(allow_ips)}")
        expected = [(addr_to_hex(addr), port) for (addr, port) in expected]
        base_args = ['-disablewallet', '-nolisten']
        if allow_ips:
            base_args += ['-rpcallowip=' + x for x in allow_ips]
        binds = ['-rpcbind='+addr for addr in addresses]
        self.nodes[0].rpchost = connect_to
        self.start_node(0, base_args + binds)
        pid = self.nodes[0].process.pid
        assert_equal(set(get_bind_addrs(pid)), set(expected))
        self.stop_nodes()

    def run_invalid_bind_test(self, allow_ips, addresses):
        '''
        Attempt to start a node with requested rpcallowip and rpcbind
        parameters, expecting that the node will fail.
        '''
        self.log.info(f'Invalid bind test for {addresses}')
        base_args = ['-disablewallet', '-nolisten']
        if allow_ips:
            base_args += ['-rpcallowip=' + x for x in allow_ips]
        init_error = 'Error: Invalid port specified in -rpcbind: '
        for addr in addresses:
            self.nodes[0].assert_start_raises_init_error(base_args + [f'-rpcbind={addr}'], init_error + f"'{addr}'")

    def run_allowip_test(self, allow_ips, rpchost, rpcport):
        '''
        Start a node with rpcallow IP, and request getnetworkinfo
        at a non-localhost IP.
        '''
        success = True
        self.log.info("Allow IP test for %s:%d" % (rpchost, rpcport))
        node_args = \
            ['-disablewallet', '-nolisten'] + \
            ['-rpcallowip='+x for x in allow_ips] + \
            ['-rpcbind='+addr for addr in ['127.0.0.1', "%s:%d" % (rpchost, rpcport)]] # Bind to localhost as well so start_nodes doesn't hang
        self.nodes[0].rpchost = None
        self.start_nodes([node_args])
        self.nodes[0].rpchost = f"{rpchost}:{rpcport}"
        # connect to node through non-loopback interface
        node = self.nodes[0].create_new_rpc_connection()
        try:
            node.getnetworkinfo()
        except NETWORK_ERRORS:
            success = False
        self.stop_nodes()
        return success

    def run_invalid_allowip_test(self):
        '''
        Check parameter interaction with -rpcallowip and -cjdnsreachable.
        RFC4193 addresses are fc00::/7 like CJDNS but have an optional
        "local" L bit making them fd00:: which should always be OK.
        '''
        self.log.info("Allow RFC4193 when compatible with CJDNS options")
        # Don't rpcallow RFC4193 with L-bit=0 if CJDNS is enabled
        self.nodes[0].assert_start_raises_init_error(
            ["-rpcallowip=fc00:db8:c0:ff:ee::/80","-cjdnsreachable"],
            "Invalid -rpcallowip subnet specification",
            match=ErrorMatch.PARTIAL_REGEX)
        # OK to rpcallow RFC4193 with L-bit=1 if CJDNS is enabled
        self.start_node(0, ["-rpcallowip=fd00:db8:c0:ff:ee::/80","-cjdnsreachable"])
        self.stop_nodes()
        # OK to rpcallow RFC4193 with L-bit=0 if CJDNS is not enabled
        self.start_node(0, ["-rpcallowip=fc00:db8:c0:ff:ee::/80"])
        self.stop_nodes()

    def run_test(self):
        if sum([self.options.run_ipv4, self.options.run_ipv6, self.options.run_nonloopback, self.options.httpunix]) > 1:
            raise AssertionError("Only one of --ipv4, --ipv6, --nonloopback and --unix can be set")

        self.log.info("Check for ipv6")
        have_ipv6 = test_ipv6_local()
        if not have_ipv6 and not (self.options.run_ipv4 or self.options.run_nonloopback or self.options.httpunix):
            raise SkipTest("This test requires ipv6 support.")

        self.log.info("Check for non-loopback interface")
        interfaces = all_interfaces()
        if not interfaces:
            raise AssertionError("all_interfaces() returned no IPv4 interfaces")
        self.non_loopback_ip = None
        for name,ip in interfaces:
            if not ip.startswith('127.'):
                self.non_loopback_ip = ip
                break
        if self.non_loopback_ip is None and self.options.run_nonloopback:
            raise SkipTest("This test requires a non-loopback ip address.")

        self.defaultport = rpc_port(0)

        if not self.options.run_nonloopback:
            if self.options.run_ipv4:
                self._run_loopback_tests()
                self.run_unsupported_unix_socket_test()
                self.run_invalid_bind_test(['127.0.0.1'], ['127.0.0.1:notaport', '127.0.0.1:-18443', '127.0.0.1:0', '127.0.0.1:65536'])
            if self.options.run_ipv6:
                self._run_loopback_tests()
                self.run_invalid_bind_test(['[::1]'], ['[::1]:notaport', '[::1]:-18443', '[::1]:0', '[::1]:65536'])
                self.run_invalid_allowip_test()
            if self.options.httpunix:
                self.run_unix_socket_tests()
        if not self.options.run_ipv4 and not self.options.run_ipv6 and not self.options.httpunix:
            if self.non_loopback_ip:
                self._run_nonloopback_tests()
            else:
                self.log.info('Non-loopback IP address not found, skipping non-loopback tests')

    def _run_loopback_tests(self):
        if self.options.run_ipv4:
            # check only IPv4 localhost (explicit)
            self.run_bind_test(['127.0.0.1'], '127.0.0.1', ['127.0.0.1'],
                [('127.0.0.1', self.defaultport)])
            # check only IPv4 localhost (explicit) with alternative port
            self.run_bind_test(['127.0.0.1'], '127.0.0.1:32171', ['127.0.0.1:32171'],
                [('127.0.0.1', 32171)])
            # check only IPv4 localhost (explicit) with multiple alternative ports on same host
            self.run_bind_test(['127.0.0.1'], '127.0.0.1:32171', ['127.0.0.1:32171', '127.0.0.1:32172'],
                [('127.0.0.1', 32171), ('127.0.0.1', 32172)])
        else:
            # check default without rpcallowip (IPv4 and IPv6 localhost)
            self.run_bind_test(None, '127.0.0.1', [],
                [('127.0.0.1', self.defaultport), ('::1', self.defaultport)])
            # check default with rpcallowip (IPv4 and IPv6 localhost)
            self.run_bind_test(['127.0.0.1'], '127.0.0.1', [],
                [('127.0.0.1', self.defaultport), ('::1', self.defaultport)])
            # check only IPv6 localhost (explicit)
            self.run_bind_test(['[::1]'], '[::1]', ['[::1]'],
                [('::1', self.defaultport)])
            # check both IPv4 and IPv6 localhost (explicit)
            self.run_bind_test(['127.0.0.1'], '127.0.0.1', ['127.0.0.1', '[::1]'],
                [('127.0.0.1', self.defaultport), ('::1', self.defaultport)])

    def run_unsupported_unix_socket_test(self):
        node = self.nodes[0]
        base_args = ['-disablewallet', '-nolisten']
        if not test_unix_socket():
            self.log.info("Unix sockets not supported, check that -rpcbind=unix: is rejected")
            unix_bind = f"unix:{tempfile.NamedTemporaryFile().name}"
            for args in ([f'-rpcbind={unix_bind}'],
                         [f'-rpcbind={unix_bind}', '-rpcallowip=127.0.0.1'],
                         [f'-rpcbind={unix_bind}', '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1']):
                # The path is interpreted as host:port
                node.assert_start_raises_init_error(base_args + args, f"Error: Invalid port specified in -rpcbind: '{unix_bind}'")

    def run_unix_socket_only_test(self, allow_ips):
        '''
        Start a node bound only to a unix socket and check that it is not
        overridden by localhost, regardless of -rpcallowip.
        '''
        node = self.nodes[0]
        unix_bind = node.http_unix_socket_path
        assert unix_bind, "Testing unix socket paths but test_framework did not set unix socket path"
        self.log.info(f"Unix socket only bind test for {unix_bind} with -rpcallowip={allow_ips}")

        base_args = ['-disablewallet', '-nolisten']
        binds = ['-rpcallowip=' + x for x in allow_ips]
        with node.assert_debug_log(
                expected_msgs=[
                    f"Binding RPC on address unix:{unix_bind}",
                    "init message: Done loading"],
                unexpected_msgs=[
                    "Option -rpcbind was ignored",
                    f"Binding RPC on address {unix_bind} failed",
                    "Binding RPC on address 127.0.0.1",
                    "Binding RPC on address [::1]"],
                timeout=node.rpc_timeout):
            self.start_nodes([base_args + binds])
        self.stop_nodes()

    def run_unix_socket_tests(self):
        node = self.nodes[0]

        # Debug log file needs to exist *before* the node starts for assert_debug_log()
        log_path = Path(node.debug_log_path)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.touch()

        # Access to unix sockets is managed by the filesystem, so -rpcallowip
        # is not required, and does not restrict unix socket clients.
        self.run_unix_socket_only_test([])
        self.run_unix_socket_only_test(['1.1.1.1'])

        # Binding any IP address still requires -rpcallowip. Without it all
        # -rpcbind values, including unix sockets, are ignored in favor of localhost.
        expected = [('127.0.0.1', self.defaultport)]
        bind_ips = ['127.0.0.1']
        if test_ipv6_local():
            expected.append(('::1', self.defaultport))
            bind_ips.append('::1')
        # Use a fresh path to ensure bitcoind doesn't create a new unix socket
        unix_bind = tempfile.NamedTemporaryFile().name
        # Clear the current unix socket path so test_framework uses TCP,
        # because we are expecting the unix socket bind to fail.
        node.http_unix_socket_path = None
        node.args = [arg for arg in node.args if not arg.startswith("-rpcbind=")]
        # Avoid conflict with other rpc_bind tests using 32171, 32172
        with node.assert_debug_log(
                expected_msgs=["Option -rpcbind was ignored because -rpcallowip was not specified"],
                unexpected_msgs=[f"Binding RPC on address {unix_bind}"]):
            self.run_bind_test(allow_ips=None,
                               connect_to='127.0.0.1',
                               addresses=[f'unix:{unix_bind}'] + bind_ips,
                               expected=expected)
        assert not os.path.exists(unix_bind)

        # Unix socket and IP address with -rpcallowip binds both
        with node.assert_debug_log(
                expected_msgs=[
                    f"Binding RPC on address unix:{unix_bind}",
                    f"Binding RPC on address 127.0.0.1"],
                unexpected_msgs=[
                    "Option -rpcbind was ignored",
                    f"Binding RPC on address unix:{unix_bind} failed"]):
            self.run_bind_test(allow_ips=['127.0.0.1'],
                               connect_to='127.0.0.1',
                               addresses=[f'unix:{unix_bind}'] + bind_ips,
                               expected=expected)
        # The node is stopped but doesn't clean up the unix socket path until restart
        assert os.path.exists(unix_bind)

    def _run_nonloopback_tests(self):
        self.log.info("Using interface %s for testing" % self.non_loopback_ip)

        # check only non-loopback interface
        self.run_bind_test([self.non_loopback_ip], self.non_loopback_ip, [self.non_loopback_ip],
            [(self.non_loopback_ip, self.defaultport)])

        # Check that connections from allowed IPs are allowed
        assert self.run_allowip_test([self.non_loopback_ip], self.non_loopback_ip, self.defaultport)
        # Otherwise we are denied
        if self.options.usecli:
            self.log.info("Skip negative IP test with CLI, because the CLI can not throw the tested exception type")
            return
        assert not self.run_allowip_test(['1.1.1.1'], self.non_loopback_ip, self.defaultport)

if __name__ == '__main__':
    RPCBindTest(__file__).main()
