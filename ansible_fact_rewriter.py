#!/usr/bin/env python3
"""
ansible_fact_rewriter.py

Zweck
-----
Dieses Tool migriert (bzw. prüft) Ansible-Facts von der alten Variable-Form

    ansible_<fact>[.<attr>...]

zur neuen Form

    ansible_facts.<fact>[.<attr>...]

über eine definierte Dateimenge (Extensions + Excludes).

Es basiert bewusst auf einem Regex-Ansatz (wie dein Bash/Perl-Script) und parst
weder YAML noch Jinja2. Dadurch wird der gleiche pragmatische Ansatz beibehalten:
Es werden alle Textstellen angepasst, die dem Muster entsprechen, inkl. in Strings,
Kommentaren, Templates etc.

Wichtiges Verhalten / Regeln
----------------------------
1) Match-Muster (FACT_PATTERN)
   - optionaler führender Punkt:   ".ansible_hostname"
   - dann "ansible_" + Name:       "ansible_distribution"
   - optionaler Rest aus ".attr":  "ansible_lsb.major"

2) Ausnahmen (SKIP_NAME_PATTERN)
   Alles, dessen Name dem Skip-Regex entspricht, wird NICHT umgeschrieben.
   Das ist 1:1 aus dem ursprünglichen Perl übernommen. Beispiele:
   - ansible_facts.*      -> name == "facts"  (bleibt unverändert)
   - ansible_play_*       -> bleibt unverändert
   - ansible_role_*       -> bleibt unverändert
   - etc.

3) Dateiscope
   - count(): zählt nur in der gleichen Dateimenge, die extended() auch bearbeiten würde
             (iter_target_files() => root-rglob, excludes, extensions).
             Damit ist count() als “Gating” korrekt (keine falschen 0 Treffer).
   - extended(): rewritet genau diese Dateimenge.

4) Schreiben
   - atomisches Schreiben pro Datei (NamedTemporaryFile + os.replace)
   - Dateimodus (chmod) wird übernommen
   - optional .bak-Backup

Logging
-------
- Default: WARNING
- -v  => INFO (zusammenfassende Infos + geänderte Dateien)
- -vv => DEBUG (zusätzlich einzelne Treffer pro Zeile in count())

Beispiele
---------
Dry-Run (nur anzeigen):
    python3 ansible_fact_rewriter.py . --dry-run -v

Ausführen (mit Backups):
    python3 ansible_fact_rewriter.py . --backup -v

Ohne count() (immer rewrite, sinnvoll wenn count nicht gewünscht):
    python3 ansible_fact_rewriter.py . --no-count -v
"""

from __future__ import annotations

import argparse
import fnmatch
import logging
import os
import re
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


LOG = logging.getLogger("ansible-fact-rewriter")

# Default-Dateitypen, die bearbeitet werden
EXTENSIONS_DEFAULT: tuple[str, ...] = ("*.j2", "*.jinja2", "*.yml", "*.yaml")

# Default-Verzeichnisse, die komplett ignoriert werden.
# Matching erfolgt per Path-Komponente (z.B. ".../.git/..." wird ausgeschlossen).
EXCLUDES_DEFAULT: tuple[str, ...] = (".git", ".github", ".tox", ".venv", "__pycache__")

# Entspricht dem Perl-Pattern (inkl. optionalem Punkt + Rest ".attr...")
FACT_PATTERN = re.compile(
    r"""
    (?P<dot>\.)?                      # optional führender Punkt
    \bansible_
    (?P<name>\w+)                     # Fact-Name
    (?P<rest>(?:\.[A-Za-z0-9_]+)*)    # 0..n ".attribut"
    """,
    re.VERBOSE,
)

# Alles was matcht, bleibt unangetastet.
SKIP_NAME_PATTERN = re.compile(
    r"^(?:facts|play_|role_|check_mode\b|version\b|run_tags\b|skip_tags\b|inventory_|galaxy_collection\b|collections\b|managed|args\b)"
)


@dataclass(slots=True)
class AnsibleFactRewriter:
    """
    Führt die Migration von ansible_<fact> nach ansible_facts.<fact> durch.

    Attribute
    ---------
    root:
        Basisverzeichnis für Suche/Rewrite.
    extensions:
        Liste von Glob-Patterns (Dateinamen), die als Ziel-Dateien gelten.
        Beispiele: "*.yml", "*.j2"
    excludes:
        Verzeichnisnamen, die in Pfad-Komponenten nicht vorkommen dürfen.
        Beispiel: ".git" ignoriert jede Datei innerhalb eines .git-Verzeichnisses.

    Typische Verwendung
    -------------------
    r = AnsibleFactRewriter(root=Path("."))
    found = r.count(sleep_seconds=0)
    if found > 0:
        r.extended(backup=True, dry_run=False)
    """
    root: Path = Path(".")
    extensions: tuple[str, ...] = EXTENSIONS_DEFAULT
    excludes: tuple[str, ...] = EXCLUDES_DEFAULT

    def count(self, *, sleep_seconds: float = 5.0) -> int:
        """
        Zählt die verbleibenden (noch nicht migrierten) Vorkommen von ansible_<fact>
        im gleichen Scope wie extended().

        Es werden nur Matches gezählt, die NICHT durch SKIP_NAME_PATTERN ausgenommen sind.
        Dadurch werden u.a. ansible_facts.* NICHT gezählt.

        Parameter
        ---------
        sleep_seconds:
            Wenn Treffer vorhanden sind, wird am Ende optional geschlafen, um Log-Ausgaben
            besser lesen zu können. Bei 0 Treffern wird NICHT geschlafen.

        Rückgabe
        --------
        int:
            Anzahl relevanter Treffer (nicht migrierte Facts).
        """
        total = 0

        for f in self.iter_target_files():
            try:
                with f.open("r", encoding="utf-8", errors="surrogateescape") as fh:
                    for lineno, line in enumerate(fh, start=1):
                        for m in FACT_PATTERN.finditer(line):
                            name = m.group("name")
                            if SKIP_NAME_PATTERN.search(name):
                                continue
                            total += 1
                            LOG.debug(
                                "%s:%d:%s -> %s",
                                self._rel(f),
                                lineno,
                                m.group(0),
                                line.rstrip(),
                            )
            except OSError as e:
                LOG.warning("Cannot read %s: %s", self._rel(f), e)

        if total == 0:
            LOG.info("No remaining ansible_<fact> occurrences found under %s.", self.root.resolve())
            return 0

        if sleep_seconds > 0:
            time.sleep(sleep_seconds)

        return total

    def extended(self, *, backup: bool = False, dry_run: bool = False) -> int:
        """
        Führt das eigentliche Rewrite durch (analog zu perl -pi aus dem Bash-Script).

        Vorgehen
        --------
        - iteriert über iter_target_files() (root-rglob, excludes, extensions)
        - ersetzt alle FACT_PATTERN-Matches über _replacement()
        - schreibt bei Änderungen atomisch zurück (oder nur report bei dry_run)

        Parameter
        ---------
        backup:
            Wenn True, wird zusätzlich eine "<datei>.<ext>.bak" Datei geschrieben.
        dry_run:
            Wenn True, werden keine Dateien geschrieben; es wird nur geloggt,
            welche Dateien geändert würden.

        Rückgabe
        --------
        int:
            Anzahl geänderter Dateien.
        """
        changed_files = 0

        for file in self.iter_target_files():
            try:
                original = file.read_text(encoding="utf-8", errors="surrogateescape")
            except OSError as e:
                LOG.warning("Cannot read %s: %s", self._rel(file), e)
                continue

            rewritten = FACT_PATTERN.sub(self._replacement, original)

            if rewritten != original:
                changed_files += 1
                LOG.info("Rewriting facts in: %s", self._rel(file))

                if not dry_run:
                    self._atomic_write(file, rewritten, backup=backup)

        if changed_files == 0:
            LOG.info("No files needed rewriting.")
        elif not dry_run:
            LOG.info("Fertig. Änderungen mit 'git diff' prüfen.")

        return changed_files

    def iter_target_files(self) -> Iterator[Path]:
        """
        Liefert alle Dateien unterhalb von root, die:
        - reguläre Dateien sind
        - nicht in exclude-Verzeichnissen liegen
        - deren Dateiname zu extensions passt

        Rückgabe
        --------
        Iterator[Path]:
            Paths zu Ziel-Dateien.
        """
        root = self.root.resolve()
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if self._is_excluded(p):
                continue
            if not self._matches_extension(p.name):
                continue
            yield p

    def _replacement(self, m: re.Match[str]) -> str:
        """
        Callback für re.sub(): erzeugt Ersatzstring pro Match.

        - Wenn der Name durch SKIP_NAME_PATTERN ausgenommen ist:
            return Original (ansible_<name><rest>)
        - sonst:
            return ansible_facts.<name><rest>

        Parameter
        ---------
        m:
            Regex-Match aus FACT_PATTERN.

        Rückgabe
        --------
        str:
            Ersatzstring für genau dieses Match.
        """
        dot = m.group("dot") or ""
        name = m.group("name")
        rest = m.group("rest") or ""

        # Ausnahmen: Original wiederherstellen
        if SKIP_NAME_PATTERN.search(name):
            return f"{dot}ansible_{name}{rest}"

        return f"{dot}ansible_facts.{name}{rest}"

    def _matches_extension(self, filename: str) -> bool:
        """
        Prüft, ob filename gegen eines der Glob-Patterns in extensions matcht.
        """
        return any(fnmatch.fnmatch(filename, pat) for pat in self.extensions)

    def _is_excluded(self, p: Path) -> bool:
        """
        Prüft, ob p in einem ausgeschlossenen Verzeichnis liegt.

        Matching-Logik:
        - ex muss als Pfad-Komponente vorkommen (z.B. ".git" in p.parts)
        """
        parts = p.parts
        return any(ex in parts for ex in self.excludes)

    def _atomic_write(self, path: Path, content: str, *, backup: bool) -> None:
        """
        Schreibt content atomisch nach path.

        Details:
        - optional: Backup in "<suffix>.bak"
        - schreibt in temp file im selben Verzeichnis (wichtig für os.replace auf gleichen FS)
        - übernimmt Dateirechte (chmod) vom Original
        """
        st = path.stat()

        if backup:
            bak = path.with_suffix(path.suffix + ".bak")
            try:
                bak.write_bytes(path.read_bytes())
            except OSError as e:
                LOG.warning("Cannot write backup %s: %s", self._rel(bak), e)

        tmp_dir = str(path.parent)
        with tempfile.NamedTemporaryFile(
            "w",
            delete=False,
            dir=tmp_dir,
            encoding="utf-8",
            errors="surrogateescape",
        ) as tf:
            tf.write(content)
            tmp_name = tf.name

        os.chmod(tmp_name, st.st_mode)
        os.replace(tmp_name, path)

    def _rel(self, p: Path) -> str:
        """
        Hilfsfunktion für Logs: Pfad relativ zu root, wenn möglich.
        """
        try:
            return str(p.resolve().relative_to(self.root.resolve()))
        except Exception:
            return str(p)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    """
    CLI-Argumente.

    - root: Basisverzeichnis
    - --no-count: count() überspringen (extended() läuft trotzdem)
    - --sleep: sleep in count() bei Treffern
    - --dry-run: nicht schreiben, nur reporten
    - --backup: .bak Backups
    - --ext/--exclude: Defaults erweitern
    - -v/-vv: INFO/DEBUG
    """
    ap = argparse.ArgumentParser(description="Rewrite ansible_<fact> -> ansible_facts.<fact> (Ansible facts fix).")
    ap.add_argument("root", nargs="?", default=".", help="ROOT directory (default: .)")
    ap.add_argument("--no-count", action="store_true", help="Skip count() before/after.")
    ap.add_argument("--sleep", type=float, default=5.0, help="Sleep seconds in count() (default: 5). Use 0 to disable.")
    ap.add_argument("--dry-run", action="store_true", help="Do not write files, only report what would change.")
    ap.add_argument("--backup", action="store_true", help="Create .bak backups when writing.")
    ap.add_argument("--ext", action="append", default=None, help="Additional extension glob (repeatable).")
    ap.add_argument("--exclude", action="append", default=None, help="Additional excluded directory name (repeatable).")
    ap.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v, -vv).")
    return ap.parse_args(argv)


def main(argv: list[str]) -> int:
    """
    Programmablauf:

    - Logging konfigurieren
    - Rewriter konfigurieren (root, ext/exclude Erweiterungen)
    - wenn --no-count:
        - extended() ausführen und Ende
      sonst:
        - count() => wenn Treffer > 0:
            - extended()
            - count() erneut
    """
    args = _parse_args(argv)

    level = logging.WARNING
    if args.verbose == 1:
        level = logging.INFO
    elif args.verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")

    r = AnsibleFactRewriter(root=Path(args.root))

    if args.ext:
        r.extensions = tuple(dict.fromkeys(r.extensions + tuple(args.ext)))
    if args.exclude:
        r.excludes = tuple(dict.fromkeys(r.excludes + tuple(args.exclude)))

    # Wenn --no-count: trotzdem ausführen (sonst wäre das Flag ein "do nothing")
    if args.no_count:
        r.extended(backup=args.backup, dry_run=args.dry_run)
        return 0

    found = r.count(sleep_seconds=args.sleep)

    if found > 0:
        r.extended(backup=args.backup, dry_run=args.dry_run)
        r.count(sleep_seconds=args.sleep)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
