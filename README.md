# Ansible Toolbox

## `check_requirements.py`

Checks for possible updates to Ansible roles that are stored in a requirements file.

```shell
cat requirements.yml
---

- name: docker
  src: bodsch.docker
  version: 3.1.2

...


/src/ansible-toolbox/check_requirements.py -r molecule/default/requirements.yml
 - docker - 3.1.2 (bodsch.docker)
   current tag 3.1.2 does not match latest available tag 3.4.3
```
