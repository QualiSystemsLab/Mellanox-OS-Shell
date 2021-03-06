#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Tests for `MellanoxOsDriver`
"""

import unittest

from cloudshell.networking.apply_connectivity.models.connectivity_result import ConnectivityErrorResponse
from mock import patch, Mock

from mellanox_os.src.driver import MellanoxOsDriver
from cloudshell.shell.core.context import ResourceCommandContext, ResourceContextDetails, ReservationContextDetails, \
    InitCommandContext

command2response = {
    'show interfaces': '''sn1-rsw-b11-20a [standalone: master] # show interfaces
Interface lo status:
   Comment:
   Admin up:           yes
   Link up:            yes
   DHCP running:       no
   IP address:         127.0.0.1
   Netmask:            255.0.0.0
   IPv6 enabled:       yes
   Autoconf enabled:   yes
   Autoconf route:     yes
   Autoconf privacy:   no
   DHCPv6 running:     no
   IPv6 addresses:     1
   IPv6 address:       ::1/128
   Speed:              N/A
   Duplex:             N/A
   Interface type:     loopback
   Interface source:   loopback
   MTU:                16436
   HW address:         N/A

   RX bytes:           5316                TX bytes:       5316
   RX packets:         53                  TX packets:     53
   RX mcast packets:   0                   TX discards:    0
   RX discards:        0                   TX errors:      0
   RX errors:          0                   TX overruns:    0
   RX overruns:        0                   TX carrier:     0
   RX frame:           0                   TX collisions:  0
                                           TX queue len:   0

Interface mgmt0 status:
   Comment:
   Admin up:           yes
   Link up:            yes
   DHCP running:       yes
   IP address:         10.21.94.236
   Netmask:            255.255.255.0
   IPv6 enabled:       yes
   Autoconf enabled:   no
   Autoconf route:     yes
   Autoconf privacy:   no
   DHCPv6 running:     no
   IPv6 addresses:     1
   IPv6 address:       fe80::268a:7ff:fe27:adb2/64
   Speed:              1000Mb/s (auto)
   Duplex:             full (auto)
   Interface type:     ethernet
   Interface source:   bridge
   MTU:                1500
   HW address:         24:8A:07:27:AD:B2

   RX bytes:           101568129           TX bytes:       197546
   RX packets:         1950694             TX packets:     801
   RX mcast packets:   0                   TX discards:    0
   RX discards:        0                   TX errors:      0
   RX errors:          0                   TX overruns:    0
   RX overruns:        0                   TX carrier:     0
   RX frame:           0                   TX collisions:  0
                                           TX queue len:   0



Eth1/1
  Admin state: Enabled
  Operational state: Down
  Last change in operational status: Never
  Description: N\A
  Mac address: 7c:fe:90:f8:e6:98
  MTU: 1500 bytes(Maximum packet size 1522 bytes)
  Fec: auto
  Flow-control: receive off send off
  Actual speed: 100 Gbps
  Width reduction mode: Not supported
  Switchport mode: access
  MAC learning mode: Enabled
  Last clearing of "show interface" counters : Never
  60 seconds ingress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec
  60 seconds egress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec

Rx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets

Tx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets


Eth1/2
  Admin state: Enabled
  Operational state: Down
  Last change in operational status: Never
  Description: N\A
  Mac address: 7c:fe:90:f8:e6:9c
  MTU: 1500 bytes(Maximum packet size 1522 bytes)
  Fec: auto
  Flow-control: receive off send off
  Actual speed: 100 Gbps
  Width reduction mode: Not supported
  Switchport mode: access
  MAC learning mode: Enabled
  Last clearing of "show interface" counters : Never
  60 seconds ingress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec
  60 seconds egress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec

Rx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets

Tx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets


Eth1/3
  Admin state: Enabled
  Operational state: Down
  Last change in operational status: Never
  Description: N\A
  Mac address: 7c:fe:90:f8:e6:90
  MTU: 1500 bytes(Maximum packet size 1522 bytes)
  Fec: auto
  Flow-control: receive off send off
  Actual speed: 100 Gbps
  Width reduction mode: Not supported
  Switchport mode: access
  MAC learning mode: Enabled
  Last clearing of "show interface" counters : Never
  60 seconds ingress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec
  60 seconds egress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec

Rx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets

Tx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets


Eth1/4
  Admin state: Enabled
  Operational state: Down
  Last change in operational status: Never
  Description: N\A
  Mac address: 7c:fe:90:f8:e6:94
  MTU: 1500 bytes(Maximum packet size 1522 bytes)
  Fec: auto
  Flow-control: receive off send off
  Actual speed: 100 Gbps
  Width reduction mode: Not supported
  Switchport mode: access
  MAC learning mode: Enabled
  Last clearing of "show interface" counters : Never
  60 seconds ingress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec
  60 seconds egress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec

Rx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets

Tx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets


Eth1/5
  Admin state: Enabled
  Operational state: Down
  Last change in operational status: Never
  Description: N\A
  Mac address: 7c:fe:90:f8:e6:88
  MTU: 1500 bytes(Maximum packet size 1522 bytes)
  Fec: auto
  Flow-control: receive off send off
  Actual speed: 100 Gbps
  Width reduction mode: Not supported
  Switchport mode: access
  MAC learning mode: Enabled
  Last clearing of "show interface" counters : Never
  60 seconds ingress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec
  60 seconds egress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec

Rx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets

Tx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets


Eth1/6
  Admin state: Enabled
  Operational state: Down
  Last change in operational status: Never
  Description: N\A
  Mac address: 7c:fe:90:f8:e6:8c
  MTU: 1500 bytes(Maximum packet size 1522 bytes)
  Fec: auto
  Flow-control: receive off send off
  Actual speed: 100 Gbps
  Width reduction mode: Not supported
  Switchport mode: access
  MAC learning mode: Enabled
  Last clearing of "show interface" counters : Never
  60 seconds ingress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec
  60 seconds egress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec

Rx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets

Tx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets


Eth1/7
  Admin state: Enabled
  Operational state: Down
  Last change in operational status: Never
  Description: N\A
  Mac address: 7c:fe:90:f8:e6:80
  MTU: 1500 bytes(Maximum packet size 1522 bytes)
  Fec: auto
  Flow-control: receive off send off
  Actual speed: 100 Gbps
  Width reduction mode: Not supported
  Switchport mode: access
  MAC learning mode: Enabled
  Last clearing of "show interface" counters : Never
  60 seconds ingress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec
  60 seconds egress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec

Rx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets

Tx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets


Eth1/8
  Admin state: Enabled
  Operational state: Down
  Last change in operational status: Never
  Description: N\A
  Mac address: 7c:fe:90:f8:e6:84
  MTU: 1500 bytes(Maximum packet size 1522 bytes)
  Fec: auto
  Flow-control: receive off send off
  Actual speed: 100 Gbps
  Width reduction mode: Not supported
  Switchport mode: access
  MAC learning mode: Enabled
  Last clearing of "show interface" counters : Never
  60 seconds ingress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec
  60 seconds egress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec

Rx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets

Tx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets


Eth1/9
  Admin state: Enabled
  Operational state: Down
  Last change in operational status: Never
  Description: N\A
  Mac address: 7c:fe:90:f8:e6:a4
  MTU: 1500 bytes(Maximum packet size 1522 bytes)
  Fec: auto
  Flow-control: receive off send off
  Actual speed: 100 Gbps
  Width reduction mode: Not supported
  Switchport mode: access
  MAC learning mode: Enabled
  Last clearing of "show interface" counters : Never
  60 seconds ingress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec
  60 seconds egress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec

Rx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets

Tx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets


Eth1/10
  Admin state: Enabled
  Operational state: Down
  Last change in operational status: Never
  Description: N\A
  Mac address: 7c:fe:90:f8:e6:a0
  MTU: 1500 bytes(Maximum packet size 1522 bytes)
  Fec: auto
  Flow-control: receive off send off
  Actual speed: 100 Gbps
  Width reduction mode: Not supported
  Switchport mode: access
  MAC learning mode: Enabled
  Last clearing of "show interface" counters : Never
  60 seconds ingress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec
  60 seconds egress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec

Rx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets

Tx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets


Eth1/11
  Admin state: Enabled
  Operational state: Down
  Last change in operational status: Never
  Description: N\A
  Mac address: 7c:fe:90:f8:e6:ac
  MTU: 1500 bytes(Maximum packet size 1522 bytes)
  Fec: auto
  Flow-control: receive off send off
  Actual speed: 100 Gbps
  Width reduction mode: Not supported
  Switchport mode: access
  MAC learning mode: Enabled
  Last clearing of "show interface" counters : Never
  60 seconds ingress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec
  60 seconds egress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec

Rx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets

Tx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets


Eth1/12
  Admin state: Enabled
  Operational state: Down
  Last change in operational status: Never
  Description: N\A
  Mac address: 7c:fe:90:f8:e6:a8
  MTU: 1500 bytes(Maximum packet size 1522 bytes)
  Fec: auto
  Flow-control: receive off send off
  Actual speed: 100 Gbps
  Width reduction mode: Not supported
  Switchport mode: access
  MAC learning mode: Enabled
  Last clearing of "show interface" counters : Never
  60 seconds ingress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec
  60 seconds egress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec

Rx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets

Tx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets


Eth1/13
  Admin state: Enabled
  Operational state: Down
  Last change in operational status: Never
  Description: N\A
  Mac address: 7c:fe:90:f8:e6:b4
  MTU: 1500 bytes(Maximum packet size 1522 bytes)
  Fec: auto
  Flow-control: receive off send off
  Actual speed: 100 Gbps
  Width reduction mode: Not supported
  Switchport mode: access
  MAC learning mode: Enabled
  Last clearing of "show interface" counters : Never
  60 seconds ingress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec
  60 seconds egress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec

Rx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets

Tx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets


Eth1/14
  Admin state: Enabled
  Operational state: Down
  Last change in operational status: Never
  Description: N\A
  Mac address: 7c:fe:90:f8:e6:b0
  MTU: 1500 bytes(Maximum packet size 1522 bytes)
  Fec: auto
  Flow-control: receive off send off
  Actual speed: 100 Gbps
  Width reduction mode: Not supported
  Switchport mode: access
  MAC learning mode: Enabled
  Last clearing of "show interface" counters : Never
  60 seconds ingress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec
  60 seconds egress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec

Rx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets

Tx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets


Eth1/15
  Admin state: Enabled
  Operational state: Down
  Last change in operational status: Never
  Description: N\A
  Mac address: 7c:fe:90:f8:e6:bc
  MTU: 1500 bytes(Maximum packet size 1522 bytes)
  Fec: auto
  Flow-control: receive off send off
  Actual speed: 100 Gbps
  Width reduction mode: Not supported
  Switchport mode: access
  MAC learning mode: Enabled
  Last clearing of "show interface" counters : Never
  60 seconds ingress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec
  60 seconds egress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec

Rx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets

Tx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets


Eth1/16/1
  Admin state: Disabled
  Operational state: Down
  Last change in operational status: Never
  Description: N\A
  Mac address: 7c:fe:90:f8:e6:b8
  MTU: 1500 bytes(Maximum packet size 1522 bytes)
  Fec: auto
  Flow-control: receive off send off
  Actual speed: 10 Gbps
  Width reduction mode: Not supported
  Switchport mode: trunk
  MAC learning mode: Enabled
  Last clearing of "show interface" counters : Never
  60 seconds ingress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec
  60 seconds egress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec

Rx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets

Tx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets


Eth1/16/2
  Admin state: Enabled
  Operational state: Up
  Last change in operational status: 3w3d and 20:03:02 ago (7 oper change)
  Description: N\A
  Mac address: 7c:fe:90:f8:e6:b9
  MTU: 1500 bytes(Maximum packet size 1522 bytes)
  Fec: auto
  Flow-control: receive off send off
  Actual speed: 10 Gbps
  Width reduction mode: Not supported
  Switchport mode: trunk
  MAC learning mode: Enabled
  Last clearing of "show interface" counters : Never
  60 seconds ingress rate: 23504 bits/sec, 2938 bytes/sec, 38 packets/sec
  60 seconds egress rate: 8 bits/sec, 1 bytes/sec, 0 packets/sec

Rx
  71512785             packets
  683728               unicast packets
  48744026             multicast packets
  22085031             broadcast packets
  5843657963           bytes
  0                    error packets
  0                    discard packets

Tx
  554                  packets
  539                  unicast packets
  15                   multicast packets
  0                    broadcast packets
  42136                bytes
  0                    error packets
  0                    discard packets


Eth1/16/3
  Admin state: Enabled
  Operational state: Up
  Last change in operational status: 3w3d and 20:03:00 ago (7 oper change)
  Description: N\A
  Mac address: 7c:fe:90:f8:e6:ba
  MTU: 1500 bytes(Maximum packet size 1522 bytes)
  Fec: auto
  Flow-control: receive off send off
  Actual speed: 10 Gbps
  Width reduction mode: Not supported
  Switchport mode: trunk
  MAC learning mode: Enabled
  Last clearing of "show interface" counters : Never
  60 seconds ingress rate: 27992 bits/sec, 3499 bytes/sec, 45 packets/sec
  60 seconds egress rate: 8 bits/sec, 1 bytes/sec, 1 packets/sec

Rx
  84840271             packets
  976620               unicast packets
  65004062             multicast packets
  18859589             broadcast packets
  6809776807           bytes
  0                    error packets
  0                    discard packets

Tx
  5383                 packets
  163                  unicast packets
  0                    multicast packets
  5220                 broadcast packets
  384002               bytes
  0                    error packets
  0                    discard packets


Eth1/16/4
  Admin state: Enabled
  Operational state: Up
  Last change in operational status: 3w3d and 20:03:01 ago (7 oper change)
  Description: N\A
  Mac address: 7c:fe:90:f8:e6:bb
  MTU: 1500 bytes(Maximum packet size 1522 bytes)
  Fec: auto
  Flow-control: receive off send off
  Actual speed: 10 Gbps
  Width reduction mode: Not supported
  Switchport mode: trunk
  MAC learning mode: Enabled
  Last clearing of "show interface" counters : Never
  60 seconds ingress rate: 24936 bits/sec, 3117 bytes/sec, 42 packets/sec
  60 seconds egress rate: 0 bits/sec, 0 bytes/sec, 0 packets/sec

Rx
  94435729             packets
  686887               unicast packets
  61126504             multicast packets
  32622319             broadcast packets
  7473484550           bytes
  0                    error packets
  0                    discard packets

Tx
  0                    packets
  0                    unicast packets
  0                    multicast packets
  0                    broadcast packets
  0                    bytes
  0                    error packets
  0                    discard packets


        ''',
    'show version': '''sn1-rsw-b11-20a [standalone: master] # show version
Product name:      MLNX-OS
Product release:   3.6.1102
Build ID:          #1-dev
Build date:        2016-06-30 17:13:47
Target arch:       x86_64
Target hw:         x86_64
Built by:          jenkins@fit-build-91
Version summary:   X86_64 3.6.1102 2016-06-30 17:13:47 x86_64

Product model:     x86onie
Host ID:           248A0727ADB2
System serial num: \\"MT1628X26331\\"
System UUID:       45c603e2-4ce8-11e6-8000-7cfe90f8e680

Uptime:            48d 0h 59m 15.328s
CPU load averages: 1.10 / 1.11 / 1.12
Number of CPUs:    4
System memory:     1902 MB used / 6037 MB free / 7939 MB total
Swap:              0 MB used / 0 MB free / 0 MB total

        ''',
    'interface ethernet 1/4 switchport mode access': '\n% Port 1/4 is part of a port channel',
}


class FakeSSHManager:
    def __init__(self):
        self._history = []

    def clear_history(self):
        self._history = []

    def get_history(self):
        return list(self._history)

    def command(self, command, prompt_regex):
        response = command2response.get(command, '') + '\nFake Prompt > #'
        self._history.append((command, response))
        if '\n%' in response.replace('\r', '\n'):
            es = 'CLI error message: ' + response
            raise Exception(es)
        return response

    def disconnect(self):
        pass


def fake_getattr(context, attribute_name):
    name2value = {
        'User': 'admin',
        'Password': 'admin',
    }
    return name2value[attribute_name]


class TestMellanoxOsDriver(unittest.TestCase):
    def setUp(self):
        self.driver = MellanoxOsDriver()
        self.fake_ssh_manager = FakeSSHManager()
        context = Mock(InitCommandContext)
        self.driver.initialize(context, ssh_manager=self.fake_ssh_manager)

    def tearDown(self):
        self.driver.cleanup()

    @patch('mellanox_os.src.driver.CloudShellAPISession')
    @patch('mellanox_os.src.driver.get_qs_logger')
    @patch('mellanox_os.src.driver.AutoLoadCommandContext')
    @patch('mellanox_os.src.driver.get_attribute_by_name', new_callable=lambda: fake_getattr)
    def test_get_inventory(self, mocked_getattr, mocked_autoload_context, mocked_get_qs_logger, mocked_csapi):
        # print 'Hello from test_get_inventory'
        # Arrange

        # Act
        result = self.driver.get_inventory(mocked_autoload_context)

        # Assert
        # for r in result.resources:
        #     print '%s %s' % (r.name, r.model)
        self.assertTrue(len(result.resources) == 23, 'Didn\'t discover 23 resources')

    @patch('mellanox_os.src.driver.CloudShellAPISession')
    @patch('mellanox_os.src.driver.get_qs_logger')
    @patch('mellanox_os.src.driver.ResourceCommandContext')
    @patch('mellanox_os.src.driver.get_attribute_by_name', new_callable=lambda: fake_getattr)
    def test_apply_connectivity_changes_connect_error(self, mocked_getattr, mocked_resource_context, mocked_get_qs_logger, mocked_csapi):
        # print 'Hello from test_apply_connectivity_changes_connect'
        connect_request = '''{"driverRequest":{"actions":[{"connectionId":"fed17449-c2dc-4213-8c17-569fe7a6c7d9","connectionParams":{"vlanId":"2","mode":"Access","vlanServiceAttributes":[{"attributeName":"Allocation Ranges","attributeValue":"2-4094","type":"vlanServiceAttribute"},{"attributeName":"Isolation Level","attributeValue":"Exclusive","type":"vlanServiceAttribute"},{"attributeName":"Access Mode","attributeValue":"Access","type":"vlanServiceAttribute"},{"attributeName":"VLAN ID","attributeValue":"","type":"vlanServiceAttribute"},{"attributeName":"Virtual Network","attributeValue":"","type":"vlanServiceAttribute"},{"attributeName":"Default VLAN","attributeValue":"","type":"vlanServiceAttribute"},{"attributeName":"QnQ","attributeValue":"False","type":"vlanServiceAttribute"},{"attributeName":"CTag","attributeValue":"","type":"vlanServiceAttribute"}],"type":"setVlanParameter"},"connectorAttributes":[{"attributeName":"Target Interface","attributeValue":"","type":"connectorAttribute"},{"attributeName":"Source Interface","attributeValue":"","type":"connectorAttribute"},{"attributeName":"Selected Network","attributeValue":"2","type":"connectorAttribute"}],"actionId":"fed17449-c2dc-4213-8c17-569fe7a6c7d9_ff77a4b5-5018-4e78-bd36-1a662e1952c5","actionTarget":{"fullName":"MellanoxOs/Chassis 1/Port 2",

        "fullAddress":"10.21.94.241/1/4","type":"actionTarget"},

        "customActionAttributes":[],"type":"setVlan"},{"connectionId":"fed17449-c2dc-4213-8c17-569fe7a6c7d9","connectionParams":{"vlanId":"2","mode":"Access","vlanServiceAttributes":[{"attributeName":"Allocation Ranges","attributeValue":"2-4094","type":"vlanServiceAttribute"},{"attributeName":"Isolation Level","attributeValue":"Exclusive","type":"vlanServiceAttribute"},{"attributeName":"Access Mode","attributeValue":"Access","type":"vlanServiceAttribute"},{"attributeName":"VLAN ID","attributeValue":"","type":"vlanServiceAttribute"},{"attributeName":"Virtual Network","attributeValue":"","type":"vlanServiceAttribute"},{"attributeName":"Default VLAN","attributeValue":"","type":"vlanServiceAttribute"},{"attributeName":"QnQ","attributeValue":"False","type":"vlanServiceAttribute"},{"attributeName":"CTag","attributeValue":"","type":"vlanServiceAttribute"}],"type":"setVlanParameter"},"connectorAttributes":[{"attributeName":"Target Interface","attributeValue":"","type":"connectorAttribute"},{"attributeName":"Source Interface","attributeValue":"","type":"connectorAttribute"},{"attributeName":"Selected Network","attributeValue":"2","type":"connectorAttribute"}],"actionId":"fed17449-c2dc-4213-8c17-569fe7a6c7d9_61c780ac-d889-4d6e-a41a-0a18ac73c125","actionTarget":{"fullName":"MellanoxOs/Chassis 1/Port 1","fullAddress":"10.21.94.241/1/1","type":"actionTarget"},"customActionAttributes":[],"type":"setVlan"}]}}'''

        haderror = False
        for r in self.driver.ApplyConnectivityChanges(mocked_resource_context, request=connect_request).driverResponse.actionResults:
            if isinstance(r, ConnectivityErrorResponse):
                haderror = True
                self.assertTrue('port channel' in r.errorMessage)

        self.assertTrue(haderror, 'Failure during connectivity update was not reported')

    @patch('mellanox_os.src.driver.CloudShellAPISession')
    @patch('mellanox_os.src.driver.get_qs_logger')
    @patch('mellanox_os.src.driver.ResourceCommandContext')
    @patch('mellanox_os.src.driver.get_attribute_by_name', new_callable=lambda: fake_getattr)
    def test_apply_connectivity_changes_connect(self, mocked_getattr, mocked_resource_context, mocked_get_qs_logger, mocked_csapi):
        # print 'Hello from test_apply_connectivity_changes_connect'
        connect_request = '''{"driverRequest":{"actions":[{"connectionId":"fed17449-c2dc-4213-8c17-569fe7a6c7d9","connectionParams":{"vlanId":"2","mode":"Access","vlanServiceAttributes":[{"attributeName":"Allocation Ranges","attributeValue":"2-4094","type":"vlanServiceAttribute"},{"attributeName":"Isolation Level","attributeValue":"Exclusive","type":"vlanServiceAttribute"},{"attributeName":"Access Mode","attributeValue":"Access","type":"vlanServiceAttribute"},{"attributeName":"VLAN ID","attributeValue":"","type":"vlanServiceAttribute"},{"attributeName":"Virtual Network","attributeValue":"","type":"vlanServiceAttribute"},{"attributeName":"Default VLAN","attributeValue":"","type":"vlanServiceAttribute"},{"attributeName":"QnQ","attributeValue":"False","type":"vlanServiceAttribute"},{"attributeName":"CTag","attributeValue":"","type":"vlanServiceAttribute"}],"type":"setVlanParameter"},"connectorAttributes":[{"attributeName":"Target Interface","attributeValue":"","type":"connectorAttribute"},{"attributeName":"Source Interface","attributeValue":"","type":"connectorAttribute"},{"attributeName":"Selected Network","attributeValue":"2","type":"connectorAttribute"}],"actionId":"fed17449-c2dc-4213-8c17-569fe7a6c7d9_ff77a4b5-5018-4e78-bd36-1a662e1952c5","actionTarget":{"fullName":"MellanoxOs/Chassis 1/Port 2","fullAddress":"10.21.94.241/1/2","type":"actionTarget"},"customActionAttributes":[],"type":"setVlan"},{"connectionId":"fed17449-c2dc-4213-8c17-569fe7a6c7d9","connectionParams":{"vlanId":"2","mode":"Access","vlanServiceAttributes":[{"attributeName":"Allocation Ranges","attributeValue":"2-4094","type":"vlanServiceAttribute"},{"attributeName":"Isolation Level","attributeValue":"Exclusive","type":"vlanServiceAttribute"},{"attributeName":"Access Mode","attributeValue":"Access","type":"vlanServiceAttribute"},{"attributeName":"VLAN ID","attributeValue":"","type":"vlanServiceAttribute"},{"attributeName":"Virtual Network","attributeValue":"","type":"vlanServiceAttribute"},{"attributeName":"Default VLAN","attributeValue":"","type":"vlanServiceAttribute"},{"attributeName":"QnQ","attributeValue":"False","type":"vlanServiceAttribute"},{"attributeName":"CTag","attributeValue":"","type":"vlanServiceAttribute"}],"type":"setVlanParameter"},"connectorAttributes":[{"attributeName":"Target Interface","attributeValue":"","type":"connectorAttribute"},{"attributeName":"Source Interface","attributeValue":"","type":"connectorAttribute"},{"attributeName":"Selected Network","attributeValue":"2","type":"connectorAttribute"}],"actionId":"fed17449-c2dc-4213-8c17-569fe7a6c7d9_61c780ac-d889-4d6e-a41a-0a18ac73c125","actionTarget":{"fullName":"MellanoxOs/Chassis 1/Port 1","fullAddress":"10.21.94.241/1/1","type":"actionTarget"},"customActionAttributes":[],"type":"setVlan"}]}}'''

        expected_commands = [
                'interface ethernet 1/2 switchport mode access',
                'interface ethernet 1/2 switchport access vlan 2',
                'vlan 2',
                'interface ethernet 1/1 switchport mode access',
                'interface ethernet 1/1 switchport access vlan 2',
                'vlan 2',
            ]

        # Arrange

        # Act
        self.driver.ApplyConnectivityChanges(mocked_resource_context, request=connect_request)

        # print '\n'.join(['%s => %s' % (a, b) for a, b in self.fake_ssh_manager.get_history()])

        # Assert
        errors = []
        seen = set([command for command, response in self.fake_ssh_manager.get_history()])
        for command in expected_commands:
            if command not in seen:
                errors.append(command)
        self.assertTrue(len(errors) == 0, 'Missing expected commands:\n%s' % '\n'.join(errors))

    @patch('mellanox_os.src.driver.CloudShellAPISession')
    @patch('mellanox_os.src.driver.get_qs_logger')
    @patch('mellanox_os.src.driver.ResourceCommandContext')
    @patch('mellanox_os.src.driver.get_attribute_by_name', new_callable=lambda: fake_getattr)
    def test_apply_connectivity_changes_disconnect(self, mocked_getattr, mocked_resource_context, mocked_get_qs_logger, mocked_csapi):
        # print 'Hello from test_apply_connectivity_changes_disconnect'
        disconnect_request = '''{"driverRequest":{"actions":[{"connectionId":"fed17449-c2dc-4213-8c17-569fe7a6c7d9","connectionParams":{"vlanId":"2","mode":"Access","vlanServiceAttributes":[{"attributeName":"Allocation Ranges","attributeValue":"2-4094","type":"vlanServiceAttribute"},{"attributeName":"Isolation Level","attributeValue":"Exclusive","type":"vlanServiceAttribute"},{"attributeName":"Access Mode","attributeValue":"Access","type":"vlanServiceAttribute"},{"attributeName":"VLAN ID","attributeValue":"","type":"vlanServiceAttribute"},{"attributeName":"Virtual Network","attributeValue":"","type":"vlanServiceAttribute"},{"attributeName":"Default VLAN","attributeValue":"","type":"vlanServiceAttribute"},{"attributeName":"QnQ","attributeValue":"False","type":"vlanServiceAttribute"},{"attributeName":"CTag","attributeValue":"","type":"vlanServiceAttribute"}],"type":"setVlanParameter"},"connectorAttributes":[{"attributeName":"Interface","attributeValue":"MellanoxOs/Chassis 1/Port 1","type":"connectorAttribute"}],"actionId":"fed17449-c2dc-4213-8c17-569fe7a6c7d9_61c780ac-d889-4d6e-a41a-0a18ac73c125","actionTarget":{"fullName":"MellanoxOs/Chassis 1/Port 1","fullAddress":"10.21.94.241/1/1","type":"actionTarget"},"customActionAttributes":[],"type":"removeVlan"},{"connectionId":"fed17449-c2dc-4213-8c17-569fe7a6c7d9","connectionParams":{"vlanId":"2","mode":"Access","vlanServiceAttributes":[{"attributeName":"Allocation Ranges","attributeValue":"2-4094","type":"vlanServiceAttribute"},{"attributeName":"Isolation Level","attributeValue":"Exclusive","type":"vlanServiceAttribute"},{"attributeName":"Access Mode","attributeValue":"Access","type":"vlanServiceAttribute"},{"attributeName":"VLAN ID","attributeValue":"","type":"vlanServiceAttribute"},{"attributeName":"Virtual Network","attributeValue":"","type":"vlanServiceAttribute"},{"attributeName":"Default VLAN","attributeValue":"","type":"vlanServiceAttribute"},{"attributeName":"QnQ","attributeValue":"False","type":"vlanServiceAttribute"},{"attributeName":"CTag","attributeValue":"","type":"vlanServiceAttribute"}],"type":"setVlanParameter"},"connectorAttributes":[{"attributeName":"Interface","attributeValue":"MellanoxOs/Chassis 1/Port 2","type":"connectorAttribute"}],"actionId":"fed17449-c2dc-4213-8c17-569fe7a6c7d9_ff77a4b5-5018-4e78-bd36-1a662e1952c5","actionTarget":{"fullName":"MellanoxOs/Chassis 1/Port 2","fullAddress":"10.21.94.241/1/2","type":"actionTarget"},"customActionAttributes":[],"type":"removeVlan"}]}}'''

        expected_commands = [
            'interface ethernet 1/1 switchport access vlan 2098',
            'interface ethernet 1/2 switchport access vlan 2098',
            'no vlan 2',
        ]
        # Arrange

        # Act
        self.driver.ApplyConnectivityChanges(mocked_resource_context, request=disconnect_request)

        # print '\n'.join(['%s => %s' % (a, b) for a, b in self.fake_ssh_manager.get_history()])

        # Assert
        errors = []
        seen = set([command for command, response in self.fake_ssh_manager.get_history()])
        for command in expected_commands:
            if command not in seen:
                errors.append(command)
        self.assertTrue(len(errors) == 0, 'Missing expected commands:\n%s' % '\n'.join(errors))


if __name__ == '__main__':
    import sys
    sys.exit(unittest.main())
