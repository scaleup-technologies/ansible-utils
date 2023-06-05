#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Sven Anders
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: opnsense_authorized_key
short_description: Adds or removes an SSH authorized key
description:
    - Adds or removes SSH authorized keys for particular user accounts.
version_added: "1.0.0"
options:
  user:
    description:
      - The username on the remote host whose authorized_keys file will be modified.
    type: str
    required: true
  key:
    description:
      - The SSH public key(s), as a string or (since Ansible 1.9) url (https://github.com/username.keys).
    type: str
    required: true
  state:
    description:
      - Whether the given key (with the given key_options) should or should not be in the file.
    type: str
    choices: [ absent, present ]
    default: present
  key_options:
    description:
      - A string of ssh key options to be prepended to the key in the authorized_keys file.
    type: str
  comment:
    description:
      - Change the comment on the public key.
      - Rewriting the comment is useful in cases such as fetching it from GitHub or GitLab.
      - If no comment is specified, the existing comment will be kept.
    type: str
author: Sven Anders
'''
EXAMPLES = r'''
- name: Set authorized key taken from file
  opnsense_authorized_key:
    user: charlie
    state: present
    key: "{{ lookup('file', '/home/charlie/.ssh/id_rsa.pub') }}"
'''


RETURN = r'''
key:
  description: The key that the module was running against.
  returned: success
  type: str
  sample: https://github.com/user.keys
key_option:
  description: Key options related to the key.
  returned: success
  type: str
  sample: null
state:
  description: Whether the given key (with the given key_options) should or should not be in the file
  returned: success
  type: str
  sample: present
unique:
  description: Whether the key is unique
  returned: success
  type: bool
  sample: false
user:
  description: The username on the remote host whose authorized_keys file will be modified
  returned: success
  type: str
  sample: user
'''
from subprocess import run
from base64 import b64encode
from ansible.module_utils.basic import AnsibleModule

def get_authorized_keys(module, username):
    php_script = r'''<?php
        require_once('config.inc');
        require_once('auth.inc');
        $a_user = &config_read_array('system', 'user');
        $found=0;
    '''
    php_script += '$username = "'+username+'";'
    php_script += r'''
      foreach ($a_user as $userent) {
        if ($userent['name'] == $username) {
            echo(base64_decode($userent['authorizedkeys']));
            $found=1;
        }
      }
      if ($found==0) {
        print('NOT_FOUND');
      }
    ''';
    r=run(['/usr/local/bin/php'], capture_output=True, input=php_script.encode('utf-8'))
    if r.returncode != 0:
        module.fail_json(msg="authorized_key can not fetched, php script for fetch returned rtn_code %d" % r.returncode)
    if r.stdout.decode('utf-8').startswith("NOT_FOUND"):
        module.fail_json(msg="User not found")
    return r.stdout.decode('utf-8').replace('\r','').split('\n')

def write_authorized_keys(module, username, lines):
    content=b64encode(('\r\n'.join(lines)).encode('utf-8'))
    php_script = r'''<?php
        require_once('config.inc');
        require_once('auth.inc');
        $a_user = &config_read_array('system', 'user');
    '''
    php_script += '$username = "'+username+'";'
    php_script += '$content = "'+content.decode('utf-8')+'";'
    php_script += r'''
      foreach ($a_user as &$userent) {
        if ($userent['name'] == $username) {
            $userent['authorizedkeys']=$content;
            local_user_set($userent);
        }
      }
      write_config(sprintf('Anible ssh authorized_key module for user %s', $username));
    '''
    r=run(['/usr/local/bin/php'], capture_output=True, input=php_script.encode('utf-8'))
    if r.returncode != 0:
        module.fail_json(msg="set ssh key rtn_code %d" % r.returncode)

def main():
    module = AnsibleModule(
        argument_spec=dict(
            user=dict(type='str', required=True),
            key=dict(type='str', required=True, no_log=False),
            state=dict(type='str', default='present', choices=['absent', 'present']),
            key_options=dict(type='str', no_log=False),
            comment=dict(type='str'),
        ),
        supports_check_mode=True,
    )

    results={}
    results['comment']=module.params['comment']
    old_keys= get_authorized_keys(module, module.params['user'])
    results['old_keys'] = old_keys
    found=False
    changed=False
    key=module.params['key']
    new_key_line=''
    if module.params['key_options'] is not None:
        new_key_line=module.params['key_options']+' '
    new_key_line+=key
    if module.params['comment'] is not None:
        new_key_line+=' '+module.params['comment']
    results['new_line']=new_key_line
    new_lines=[]
    for old_key_line in old_keys:
        if module.params['key'] in old_key_line:
            found=True
            if module.params['state']=='present':
                if old_key_line != new_key_line:
                    changed=True
                new_lines.append(new_key_line)
            else: # absent
                # delete line, do not append
                changed=True
        else:
            new_lines.append(old_key_line)
    if not found and module.params['state']=='present':
      new_lines.append(new_key_line)
      changed=True
    results['changed']=changed
    if changed:
        sanitized_before = {}
        sanitized_after = {}
        if not module.check_mode:
            write_authorized_keys(module, module.params['user'], new_lines)
            sanitized_before['lines']="\n".join(old_keys)
            sanitized_after['lines']="\n".join(new_lines)
        if module._diff:
            results["diff"] = {
                "before": sanitized_before,
                "after": sanitized_after,
            }

    module.exit_json(**results)

if __name__ == '__main__':
    main()
