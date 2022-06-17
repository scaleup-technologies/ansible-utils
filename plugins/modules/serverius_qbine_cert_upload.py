#!/usr/bin/python
# -*- coding: utf-8 -*-
# see https://api.serverius.net/

DOCUMENTATION = '''
This tasks uploads an Certificate+Key to qbine and sets an description with a sha256 hash of the
uploaded material. With the hash it is able to evaluate if an upload is needed.
'''

EXAMPLES = '''
- name: Serverius upload
  serverius_qbine_cert_upload:
    user: "{{ serverius_user }}"
    secret: "{{ serverius_password }}"
    api_url: https://api.serverius.net
    domain_name_uuid: "{{ letsencrypt_key.serverius_qbine_uuid }}"
    keyfile: "/etc/letsencrypt/certs/{{ letsencrypt_key.name }}/privkey.key"
    certfile: "/etc/letsencrypt/certs/{{ letsencrypt_key.name }}/fullchain.pem"
'''
# import module snippets
from ansible.module_utils.basic import *

try:
    import requests
    import json
    import base64
    import hashlib

    IMPORT_SUCCESS = True
except ImportError:
    IMPORT_SUCCESS = False

def read_file(filename, module):
    try:
        file=open(filename,'r')
        content="\n".join(file.readlines())
        file.close()
    except FileNotFoundError:
        module.fail_json(msg='File %s not found' % filename)
    return content

def calc_description(key,cert):
    m = hashlib.sha256()
    m.update(key.encode('ascii'))
    m.update(cert.encode('ascii'))
    return "Uploaded key by ansible with sha256: %s" % m.hexdigest()

def main():
    module = AnsibleModule(
        argument_spec=dict(
            user=dict(type="str", required=True),
            secret=dict(type="str", required=True, no_log=True),
            api_url=dict(type="str", default="https://api.serverius.net"),
            domain_name_uuid=dict(type="str", required=True),
            keyfile=dict(type="str", required=True),
            certfile=dict(type="str", required=True),
        ),
        supports_check_mode=True,
    )
    if not IMPORT_SUCCESS:
        module.fail_json(msg="python libs must be installed to use this module.")
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'accept': 'application/json'
    }
    params=module.params
    token_url="%s/auth/oauth/v2/token" % params['api_url']
    token_data={
        'grant_type': 'client_credentials',
        'client_id': params['user'],
        'client_secret': params['secret']
    }
    r = requests.post(token_url, data=token_data, headers=headers)
    token=r.json()['access_token']

    headers['Authorization']='Bearer %s' % token

    enc_url= "%s/waf/v2/domain-name/%s/encryption-file" % ( params['api_url'], params['domain_name_uuid'] )
    r = requests.get(enc_url, headers=headers)
    enc_answer=r.json()
    changed=False
    key=read_file(params['keyfile'],module)
    cert=read_file(params['certfile'], module)
    description=calc_description(key,cert)

    if type(enc_answer) == str:
        if enc_answer == "No encryption file for this domain":
            changed = True
        else:
            module.fail_json(msg="unkown result %s" % enc_answer)
    else:
        if ('description' not in enc_answer) or (enc_answer['description']!=description):
            changed=True
    result={}
    if changed and module.check_mode==False:
        upload_data={
            "description": description,
            "dontverify": False,
            "key": base64.b64encode(key.encode('ascii')).decode('ascii'),
            "cert": base64.b64encode(cert.encode('ascii')).decode('ascii'),
        }
        r = requests.put(enc_url, data=upload_data, headers=headers)
        result=r.json()
    module.exit_json(changed=changed, enc_answer=enc_answer, result=result)

if __name__ == '__main__':
    main()
