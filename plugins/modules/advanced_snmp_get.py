#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
from pprint import pprint
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type

DOCUMENTATION = r'''
'''

EXAMPLES = r'''
'''

RETURN = r'''
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
                        items[str(var_bind[0])] = str(var_bind[1])
                if len(items.keys()) > 0:
                    result.append(items)
            else:
                raise RuntimeError(
                    'Got SNMP error: {0}'.format(error_indication))
        except StopIteration:
            break
    return result


def snmp_get(target, oids, credentials, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
    handler = hlapi.getCmd(
        engine,
        credentials,
        hlapi.UdpTransportTarget((target, port)),
        context,
        *construct_object_types(oids)
    )
    return snmp_fetch(handler, 1)[0]


def snmp_bulk_walk(target, bulk_block, credentials, port=161, engine=hlapi.SnmpEngine(), context=hlapi.ContextData()):
    nonRepeaters = 0
    maxRepetitions = 25
    first_key = list(bulk_block.keys())[0]
    first_oid = bulk_block[first_key]['oid']
    handler = hlapi.bulkCmd(engine, credentials,
                            hlapi.UdpTransportTarget((target, port)),
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


def value_end_calc(value, field_dict):
    dest_type = 'str'
    if 'type' in field_dict:
        dest_type = field_dict['type']
    if dest_type == 'int':
        value = int(value)
    elif dest_type == 'float':
        value = float(value)
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
