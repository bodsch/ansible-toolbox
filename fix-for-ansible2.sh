#!/usr/bin/env bash

set -euo pipefail

ROOT="${1:-.}"

# Dateitypen, in denen wir suchen
EXTENSIONS=(
  "*.j2"
  "*.jinja2"
  "*.yml"
  "*.yaml"
)

# Verzeichnisse, die ignoriert werden sollen
EXCLUDES=(
  ".git"
  ".github"
  ".tox"
  ".venv"
  "__pycache__"
)


count() {

  if [ -d plugins ]
  then
    grep -nr "ansible_" plugins/*
  else
    grep -nr "ansible_" tasks/*
  fi

  sleep 5s
}

simple() {

  sed -i 's|ansible_distribution_major_version|ansible_facts.distribution_major_version|g' roles/*/tasks/*.yaml
  sed -i 's|ansible_distribution_major_version|ansible_facts.distribution_major_version|g' roles/*/tasks/*.yml

  sed -i 's|ansible_distribution|ansible_facts.distribution|g' roles/*/tasks/*.yml
  sed -i 's|ansible_distribution|ansible_facts.distribution|g' roles/*/tasks/*.yaml
  sed -i 's|ansible_distribution|ansible_facts.distribution|g' roles/*/tasks/*/.yaml
  sed -i 's|ansible_distribution|ansible_facts.distribution|g' roles/*/tasks/*/*.yml
  sed -i 's|ansible_distribution|ansible_facts.distribution|g' roles/*/molecule/*/*.yml

  sed -i 's|ansible_os_family|ansible_facts.os_family|g' roles/*/molecule/*/*.yml
  sed -i 's|ansible_os_family|ansible_facts.os_family|g' roles/*/tasks/*.yml
  sed -i 's|ansible_os_family|ansible_facts.os_family|g' roles/*/tasks/*.yaml
  sed -i 's|ansible_os_family|ansible_facts.os_family|g' roles/*/tasks/*/*.yml

  sed -i 's|ansible_service_mgr|ansible_facts.service_mgr|g' roles/*/tasks/*/*.yml
  sed -i 's|ansible_service_mgr|ansible_facts.service_mgr|g' roles/*/tasks/*/*.yaml
  sed -i 's|ansible_service_mgr|ansible_facts.service_mgr|g' roles/*/tasks/*.yml
  sed -i 's|ansible_service_mgr|ansible_facts.service_mgr|g' roles/*/tasks/*.yaml
  sed -i 's|ansible_service_mgr|ansible_facts.service_mgr|g' roles/*/handlers/*.yml
  sed -i 's|ansible_service_mgr|ansible_facts.service_mgr|g' plugins/modules/*.py

  sed -i 's|ansible_fqdn|ansible_facts.fqdn|g' roles/openvpn/README.md
  sed -i 's|ansible_fqdn|ansible_facts.fqdn|g' roles/openvpn/*/*.yml
}


extended() {

  # find-Kommando bauen
  find_cmd=(find "$ROOT" -type f)
  for e in "${EXCLUDES[@]}"; do
    find_cmd+=( ! -path "*/$e/*" )
  done

  # Extensions anhängen
  find_cmd+=( \( )
  for i in "${!EXTENSIONS[@]}"; do
    if [[ $i -gt 0 ]]; then
      find_cmd+=( -o )
    fi
    find_cmd+=( -name "${EXTENSIONS[$i]}" )
  done
  find_cmd+=( \) )

  "${find_cmd[@]}" | while read -r file; do
    echo "Rewriting facts in: $file"

    perl -pi -e '
      s{
        (\.)?                        # 1: optional führender Punkt (z.B. hostvars[h].ansible_hostname)
        \bansible_                   # Schlüsselwort
        (\w+)                        # 2: Name (hostname, distribution, ...)
        ((?:\.[A-Za-z0-9_]+)*)       # 3: Rest: 0..n ".attribut" (KEIN nackter Punkt möglich)
      }{
        my ($dot,$name,$rest) = ($1 // "", $2, $3 // "");

        # EINZIGE Stelle für Ausnahmen:
        # alles, was hier matched, wird NICHT umgeschrieben
        if ($name =~ /^(?:facts|play_|role_|check_mode\b|version\b|run_tags\b|skip_tags\b|inventory_|galaxy_collection\b|collections\b|managed\b)/) {
          # Original wiederherstellen
          "${dot}ansible_${name}${rest}";
        } else {
          # Normaler Fact -> ansible_facts["name"]...
          "${dot}ansible_facts.${name}${rest}";
        }
      }egx;
    ' "$file"
  done

  echo "Fertig. Änderungen mit 'git diff' prüfen."
}


count
extended

count
