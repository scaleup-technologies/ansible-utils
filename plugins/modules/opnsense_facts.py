#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Sven Anders
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import re
import ipaddress
import xml.etree.ElementTree as ET
from ansible.module_utils.basic import AnsibleModule
from base64 import b64encode
from subprocess import run
__metaclass__ = type


DOCUMENTATION = r'''
---
module: opnsense_facts
short_description: Get facts from opnsense
description:
    - Get facts form opnsense
version_added: "1.0.0"
options: []
author: Sven Anders
'''
EXAMPLES = r'''
- name: Get OpnSense Fact
  opnsense_facts:
'''


RETURN = r'''
interfaces:
  description: Array of interfaces
  returned: success
  type: array
  example:
    - descr: "MGMNetHamburg",
      enable: true,
      if: "ix1_vlan923",
      ip: [],
      mac: "90:e2:ba:2c:e6:81",
      vlan_id: 923,
      vlan_parent: "ix1",
      vlan_proto: "802.1q"
    - descr: "AdminHamburg",
      enable: true,
      if: "ix1_vlan409",
      ip: [],
      mac: "90:e2:ba:2c:e6:81",
      vlan_id: 409,
      vlan_parent: "ix1",
      vlan_proto: "802.1q"

'''


def recursive_dict(element):
    return element.tag, \
        dict(map(recursive_dict, element)) or element.text


def main():
    module = AnsibleModule(
        argument_spec=dict(
        ),
        supports_check_mode=True,
    )

    results = {}
    ansible_facts = {}
    tree = ET.parse("/conf/config.xml")
    root = tree.getroot()
    interfaces_tree = root.find("interfaces")
    vip_tree = root.find("virtualip")
    # count=0
    #context = etree.iterwalk(interfaces_tree, events=("start", "end"))
    # for action, elem in context:
    #    ansible_facts['xx_%d' % count]="%s %s" % (action, elem.tag)
    #    count=count+1
    (tag, data) = recursive_dict(interfaces_tree)
    vip_data = recursive_dict(vip_tree)
    interfaces = []
    for k in data.keys():
        if 'descr' not in data[k] or 'if' not in data[k]:
            continue
        interface = {}
        interface['if'] = data[k]['if']
        interface['descr'] = data[k]['descr']

        if 'enable' in data[k].keys() and data[k]['enable'] == '1':
            interface['enable'] = True
        else:
            interface['false'] = True
        interface['ip'] = []
        if 'ipaddr' in data[k].keys():
            ipi = ipaddress.ip_interface(
                "%s/%s" % (data[k]['ipaddr'], data[k]['subnet']))
            interface['ip'].append({
                'addr': data[k]['ipaddr'],
                'subnet': data[k]['subnet'],
                'network': str(ipi.network).split('/')[0],
                'broadcast': str(ipi.network.broadcast_address),
                'netmask': str(ipi.netmask),
                'mode': 'if'
            })
        if 'ipaddrv6' in data[k].keys() and 'subnetv6' in data[k].keys():
            ipi = ipaddress.ip_interface(
                "%s/%s" % (data[k]['ipaddrv6'], data[k]['subnetv6']))
            interface['ip'].append({
                'addr': data[k]['ipaddrv6'],
                'subnet': data[k]['subnetv6'],
                'network': str(ipi.network).split('/')[0],
                'broadcast': str(ipi.network.broadcast_address),
                'netmask': str(ipi.netmask),
                'mode': 'if'
            })
        for ele in vip_tree.findall('vip'):
            (tag, ce) = recursive_dict(ele)
            if ce['interface'] == k:
                ipi = ipaddress.ip_interface(
                    "%s/%s" % (ce['subnet'], ce['subnet_bits']))
                interface['ip'].append({
                    'addr': ce['subnet'],
                    'subnet': ce['subnet_bits'],
                    'network': str(ipi.network).split('/')[0],
                    'broadcast': str(ipi.network.broadcast_address),
                    'netmask': str(ipi.netmask),
                    'mode': ce['mode']
                })
        cmd_ifconfig = run(
            ['/sbin/ifconfig', data[k]['if']], capture_output=True)
        for line in cmd_ifconfig.stdout.decode('utf-8').split('\n'):
            m = re.match("\s*ether (..:..:..:..:..:..)", line)
            if m:
                interface['mac'] = m.group(1)
            m = re.match(
                "\s*vlan: (\d+) vlanproto: (.*) vlanpcp: 0 parent interface: (.*)", line)
            if m:
                interface['vlan_id'] = int(m.group(1))
                interface['vlan_proto'] = m.group(2)
                interface['vlan_parent'] = m.group(3)

        interfaces.append(interface)

    ansible_facts['interfaces'] = interfaces
    c = []
    for ele in vip_tree.findall('vip'):
        (tag, ce) = recursive_dict(ele)
        c.append(ce)
    results['ansible_facts'] = ansible_facts

    module.exit_json(**results)


if __name__ == '__main__':
    main()
