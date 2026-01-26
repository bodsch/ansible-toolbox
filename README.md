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

## `agc_install.py`

ansible-galaxy-Fallback nach dem Forum-Workaround 
(GitHub klonen → ansible-galaxy collection build → lokale .tar.gz installieren). 

Der Fallback installiert optional auch Abhängigkeiten, ohne Galaxy zu kontaktieren 
(per --no-deps + eigene Dependency-Installation). 

Der Workaround ist in dem verlinkten Post beschrieben.

### Standardweg, bei Fehler automatisch Workaround (wie im Forum beschrieben)
```bash
./agc_install.py community.docker --force
```

### Exakte Version
```bash
./agc_install.py community.docker==5.0.5 --force
```

### Oder via Flag
```bash
./agc_install.py community.docker --version 5.0.5 --force
```

### Workaround erzwingen
```bash
./agc_install.py community.docker --mode workaround --force
```

### Wenn du Dependencies im Workaround komplett überspringen willst:
```bash
./agc_install.py community.docker --version 5.0.5 --force --deps-mode none
```

### Repo-Mapping (falls weitere Collections ein nicht-triviales Repo haben):
```bash
cat > repo-map.json <<'JSON'
{
  "community.library_inventory_filtering_v1": "https://github.com/ansible-collections/community.library_inventory_filtering"
}
JSON

./agc_install.py community.docker --version 5.0.5 --force --repo-map repo-map.json
```

### Standard erzwingen (kein Fallback)
```bash
./agc_install.py community.docker --mode galaxy --force
```
