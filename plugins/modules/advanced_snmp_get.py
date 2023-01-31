#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
from pprint import pprint, pformat
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type

DOCUMENTATION = r'''
module: advanced_snmp_get
short_description: Get SNMP Data from devices with lists, calculation
version_added: 1.2.0
description: |
  Get SNMP Data from devices, like IDRAC, Switches, group by lists, make divisions.
options:
  host:
    description: Hostname or IP address of the device
    required: true
    type: str
  community:
    description: SNMP Community
    required: true
    default: public
    type: str
  snmp:
    type: dict
    description: SNMP OIDS to get
    suboptions:
      oid:
        required: true
        type: str
        description: OID to get
      type:
        description: type to convert to
        choices:
          - str
          - int
          - float
        default: str
      divide_by:
        description: divide the value
        type: float
  snmp_bulk_blocks:
    type: dict
    description: SNMP Blocks to get (see SNMP for syntax of a block)
'''

EXAMPLES = r'''
    - name: Get values from dell idrac
      scaleuptechnologies.utils.advanced_snmp_get:
        host: 172.18.0.39
        community: public
        snmp:
          service_tag:
            oid: "1.3.6.1.4.1.674.10892.5.1.3.2.0"
          express_code:
            oid: "1.3.6.1.4.1.674.10892.5.1.3.3.0"
          model:
            oid: "1.3.6.1.4.1.674.10892.5.1.3.12.0"
          bios_version:
            oid: "1.3.6.1.4.1.674.10892.5.4.300.50.1.8.1.1"
        snmp_bulk_blocks:
          power_supply:
            slot:
              oid: "1.3.6.1.4.1.674.10892.5.4.600.12.1.15.1"
            ratedWatt:
              oid: "1.3.6.1.4.1.674.10892.5.4.600.12.1.14.1"
              type: float
              divide_by: 10
'''

RETURN = r'''
data:
  description: The SNMP Data from the device
  type: complex
  returned: always
  sample:
    bios_version: "2.4.2"
    express_code: "13043577818"
    model: "PowerEdge R420"
    service_tag: "5ZPT522"
    power_supply:
        - ratedWatt: 666.0
          slot: "PSU.Slot.1"
        - ratedWatt: 666.0
          slot: "PSU.Slot.2"
'''

try:
    from pysnmp import hlapi
    IMPORT_SUCCESS = True
except ImportError:
    IMPORT_SUCCESS = False

# Helpfull article for snmp https://www.ictshore.com/sdn/python-snmp-tutorial/


def construct_object_types(list_of_oids):
    object_types = []
    for oid in list_of_oids:
        object_types.append(hlapi.ObjectType(hlapi.ObjectIdentity(oid)))
    return object_types

def udp_transport(host,port):
    return hlapi.UdpTransportTarget((host, port),timeout=2)

def snmp_fetch(handler, count, prefix_to_check=None):
    result = []
    doit = True
    for i in range(count):
        try:
            error_indication, error_status, error_index, var_binds = next(
                handler)
            if not error_indication and not error_status:
                items = {}
                for var_bind in var_binds:
                    if prefix_to_check is not None:
                        doit = (str(var_bind[0]).startswith(prefix_to_check))
                    if doit:
                        items[str(var_bind[0])] = var_bind[1].prettyPrint()
                if len(items.keys()) > 0:
                    result.append(items)
            else:
                raise RuntimeError(
                    'Got SNMP error: {0}'.format(error_indication))
        except StopIteration:
            break
    return result


def snmp_get(target, oids, credentials, port=161, engine=hlapi.SnmpEngine(),
             context=hlapi.ContextData()):
    handler = hlapi.getCmd(
        engine,
        credentials,
        udp_transport(target, port),
        context,
        *construct_object_types(oids)
    )
    return snmp_fetch(handler, 1)[0]


def snmp_bulk_walk(target, bulk_block, credentials, port=161,
                   engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
    nonRepeaters = 0
    maxRepetitions = 25
    first_key = list(bulk_block.keys())[0]
    first_oid = bulk_block[first_key]['oid']
    handler = hlapi.bulkCmd(engine, credentials,
                            udp_transport(target, port),
                            context,
                            nonRepeaters, maxRepetitions,
                            hlapi.ObjectType(hlapi.ObjectIdentity(first_oid)))
    entries = snmp_fetch(handler, 25, first_oid)
    rtn_list = []
    for entry in entries:
        rtn = {}
        full_oid = list(entry.keys())[0]
        suffix = full_oid.replace(first_oid, '')
        rtn[first_key] = value_end_calc(entry[full_oid], bulk_block[first_key])
        for entry_key in list(bulk_block.keys())[1:]:
            oid = "%s%s" % (bulk_block[entry_key]['oid'], suffix)
            snmp_rtn = snmp_get(target, [oid], credentials)
            rtn[entry_key] = value_end_calc(
                snmp_rtn[oid], bulk_block[entry_key])
        rtn_list.append(rtn)
    return rtn_list

def int_to_mac(macint):
    if type(macint) != int:
        raise ValueError('invalid integer')
    return ':'.join(['{}{}'.format(a, b)
                     for a, b
                     in zip(*[iter('{:012x}'.format(macint))]*2)])


def value_end_calc(value, field_dict):
    dest_type = 'str'
    if 'type' in field_dict:
        dest_type = field_dict['type']
    if dest_type == 'int':
        value = int(value)
    elif dest_type == 'float':
        value = float(value)
    elif dest_type == 'mac_address':
      if value!='':
        if not(value.startswith('0x')):
          raise RuntimeError('Wrong macAddress Format %s'% value)
        value = int_to_mac(int(value,base=16)).upper()
    elif dest_type != 'str':
        raise RuntimeError('Wrong type %s ' % dest_type)
    if 'divide_by' in field_dict:
        value = value/field_dict['divide_by']
    return value


def run_module():
    module = AnsibleModule(
        argument_spec=dict(
            host=dict(type="str", required=True),
            community=dict(type="str", default='public'),
            snmp=dict(type="dict"),
            snmp_bulk_blocks=dict(type=dict),
        ), supports_check_mode=True
    )
    if not IMPORT_SUCCESS:
        module.fail_json(
            msg="python libs must be installed to use this module.")

    community = hlapi.CommunityData(module.params['community'])
    rtn = {}
    oids = []
    for snmp_name in module.params['snmp'].keys():
        oids.append(module.params['snmp'][snmp_name]['oid'])
    snmp_rtn = snmp_get(module.params['host'], oids, community)
    for snmp_name in module.params['snmp'].keys():
        val = snmp_rtn[module.params['snmp'][snmp_name]['oid']]
        rtn[snmp_name] = value_end_calc(val, module.params['snmp'][snmp_name])
    for snmp_bulk_block_name in module.params['snmp_bulk_blocks'].keys():
        block = module.params['snmp_bulk_blocks'][snmp_bulk_block_name]
        rtn[snmp_bulk_block_name] = snmp_bulk_walk(
            module.params['host'], block, community)
    module.exit_json(changed=False, data=rtn)


def main():
    run_module()


if __name__ == '__main__':
    main()
