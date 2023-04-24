#!/usr/bin/env python3

import os
import re
import yaml
# import traceback
import argparse
import git
import requests
from packaging.version import parse as parseVersion


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class RequirementsHandler():

    def __init__(self):
        """
        """
        self.args = {}
        self.parse_args()

        self.fix_version = self.args.fix

        self.git_client = git.cmd.Git()

        self.requirement_file = self.args.requirements

        if self.requirement_file:
            self.read_requirements(os.path.join(".", self.requirement_file))
        else:
            """
            """
            self.regex = re.compile('(requirements.y*ml$)')
            self.find_requirements(self.args.directory)

    def parse_args(self):
        p = argparse.ArgumentParser(description='check updates for ansible requirements')

        p.add_argument(
            "-d",
            "--directory",
            required=False,
            help="directory to find requirements file(s)",
            default='.'
        )
        p.add_argument(
            "-r",
            "--requirements",
            required=False,
            help="requirements file",
            default=""
        )
        p.add_argument(
            "-f",
            "--fix",
            required=False,
            help="fix versions",
            default=False
        )

        self.args = p.parse_args()

    def find_requirements(self, rootdir):
        """
        """
        found = []

        for ext in ["yml", "yaml"]:
            f = f"requirements.{ext}"
            if os.path.exists(f):
                print(f"file: {f}")
                found.append(os.path.join(f"./{f}"))
                # self.read_requirements(os.path.join(f))
                print("")

        for root, dirs, files in os.walk(rootdir):
            if (".tox" in root):
                continue

            for file in files:
                if self.regex.match(file):
                    found.append(os.path.join(root, file))

        found = sorted(found)
        found = list(dict.fromkeys(found))

        for f in found:
            print(f"{bcolors.OKCYAN}{bcolors.BOLD}-> file: {f}{bcolors.ENDC}")
            self.read_requirements(f)
            print("")

    def read_requirements(self, filename):
        """
        """
        with open(filename) as file:
            content = yaml.load(file, Loader=yaml.FullLoader)
            if (content):
                self.scan_requirements(content)

    def scan_requirements(self, content):
        """
        """
        if content:
            if isinstance(content, dict):
                roles = content.get("roles", [])
                if isinstance(roles, list):
                    for c in roles:
                        self.parse_ansible_role(c)

            if isinstance(content, list):
                for c in content:
                    self.parse_ansible_role(c)

    def parse_ansible_role(self, role={}):
        """
        """
        if isinstance(role, dict):
            name = role.get('name')
            src  = role.get('src')
            version = role.get('version', "unknown")

            msg = f" - {bcolors.OKBLUE}{name} - {version}{bcolors.ENDC} ({src})"

            # if version:
            #    msg = msg + f" - {version}"

            print(msg)
            # print(f" - {name} ({src}) - {version}")

            if src.startswith("http://") or src.startswith("https://") or src.startswith("git://"):
                self.git_information(src, version)
                pass
            elif src.startswith("ssh://"):
                print(f"   {bcolors.OKCYAN}ssh url are not supported{bcolors.ENDC}")
                pass
            elif src.startswith("git@"):
                print(f"   {bcolors.OKCYAN}git url are not supported{bcolors.ENDC}")
                pass
            else:
                # print(f"  {bcolors.FAIL} src {src} is not a valid git link{bcolors.ENDC}")
                url = self.get_url_from_galaxy_name(src)
                if url:
                    self.git_information(url, version)
                else:
                    print(f"   {bcolors.OKCYAN}no valid github url found{bcolors.ENDC}")

    def git_information(self, repository, version = None):
        """
        """
        # remote_refs = {}

        if version in ["master", "main"]:
            print(f"   {bcolors.WARNING}found repo that is set to \"{version}\" tag, not a version string{bcolors.ENDC}")

        try:
            tag_list = self.git_client.ls_remote("--tags", repository).split('\n')

            sorted_tags = self.__sort_git_tags(tag_list)

            if sorted_tags:
                last_tag = sorted_tags[-1:][0]  # tag_list[-1:][0].split('/')[-1:][0]

                if version and version != last_tag:
                    print(f"   {bcolors.WARNING}current tag {version} does not match latest available tag {last_tag}{bcolors.ENDC}")
                elif version and version == last_tag:
                    print(f"   {bcolors.OKGREEN}current tag {version} is up to date{bcolors.ENDC}")
                else:
                    print(f"   {bcolors.WARNING}latest available tag {last_tag}{bcolors.ENDC}")
            else:
                pass

        except Exception as exc:
            print("ERROR: {}".format(exc))
            pass

    def get_url_from_galaxy_name(self, galaxy_name):
        """
        """
        namespace, role_name = galaxy_name.split(".")

        url = f"https://galaxy.ansible.com/api/v1/roles/?owner__username={namespace}&name={role_name}"
        data = requests.get(url).json()

        results = data.get("results")

        if len(results) > 0:
            """
            """
            result = data.get('results', [])[0]

            github_user = result.get('github_user')
            github_repo = result.get('github_repo')

            return f"https://github.com/{github_user}/{github_repo}"
        else:
            return None

    def __sort_git_tags(self, data):
        """
          sort al ist of git tags
        """
        if isinstance(data, list):
            if len(data) == 1 and data[0] == "":
                return None

        versions = []
        for tag in data:
            version = tag.split('/')[-1:][0]
            if version.endswith("^{}"):
                continue
            versions.append(version)

        _versions = self.version_sort(versions)

        return _versions

    def version_sort(self, version_list):
        """
        """
        version_list.sort(key = parseVersion)

        return version_list


if __name__ == '__main__':
    """
    """
    r = RequirementsHandler()
