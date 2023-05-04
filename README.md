# Ansible Toolbox

## `check_requirements.py`

Checks for possible updates to Ansible roles that are stored in a requirements file.

It tolerates file extensions such as `.yml` or `.yaml`.


```bash
$ cat requirements.yml
---

- name: docker
  src: bodsch.docker
  version: 3.1.2

...


$ /src/ansible-toolbox/check_requirements.py -r molecule/default/requirements.yml
 - docker - 3.1.2 (bodsch.docker)
   current tag 3.1.2 does not match latest available tag 3.4.3
```

The script can also search the working directory recursively and check all 
`requirements.yml` files.

```bash
$ /src/ansible-toolbox/check_requirements.py
-> file: ./molecule/default/requirements.yml
 - docker - 3.4.3 (bodsch.docker)
   current tag 3.4.3 is up to date

-> file: ./molecule/many-properties/requirements.yml
 - docker - 3.4.3 (bodsch.docker)
   current tag 3.4.3 is up to date
```

The requirements.yml can either use a `roles` anchor


```bash
---
roles:
  - name: docker
    src: bodsch.docker
    version: 3.1.2
```

or the roles are stored flat:

```bash
---
- name: docker
  src: bodsch.docker
  version: 3.1.2
```

Furthermore, direct http(s) URLs are also respected:

```bash
$ cat ./molecule/upgrade/requirements.yml
---

- name: grafana
  src: https://github.com/cloudalchemy/ansible-grafana.git
  scm: git
  version: 0.17.0


$ /src/ansible-toolbox/check_requirements.py
-> file: ./molecule/upgrade/requirements.yml
 - grafana - 0.17.0 (https://github.com/cloudalchemy/ansible-grafana.git)
   current tag 0.17.0 does not match latest available tag 0.18.0
```

Git URLs unfortunately do not work! :(
