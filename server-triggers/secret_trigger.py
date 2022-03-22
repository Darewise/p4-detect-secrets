"""Perforce trigger to prevent secret from entering into the source control

Build to be used as a `shelve-commit` trigger. (warning! place it BEFORE the swarm shelve-commit to avoid having secrets stored in swarm history!
Can also be used as a `change-content` trigger if you specify the --is-change-content argument

requirement:
- python3
- pip package detect-secrets==1.0.3
- detect_secrets_utils.py

Can also be use

register it using `p4 triggers`
    secret_shelve shelve-commit //yourDepotPath/... "python3 secret_trigger.py %user% %client% %change% [-g swarm_review_exclusion]"
# or/and
    secret_commit change-content //yourDepotPath/... "python3 secret_trigger.py %user% %client% %change% --is-change-content [-g swarm_review_exclusion]"
"""

from P4 import P4
from datetime import datetime, timedelta
from detect_secrets import SecretsCollection
from detect_secrets.core import baseline
from detect_secrets.core.log import log
from detect_secrets.core.scan import _process_line_based_plugins
from detect_secrets.pre_commit_hook import pretty_print_diagnostics
from detect_secrets.settings import default_settings
from detect_secrets.transformers import get_transformed_file
from detect_secrets.types import NamedIO
from typing import Dict, Any, cast, Generator, List
import argparse
import io
import json
import re
import sys


SECRET_BASELINE = ".secrets.baseline"

FILE_EXCLUSION_REGEX = [
    re.compile(regex)
    for regex in [
        r".*\.(uasset|umap|exe|so|a|o|bmp|BMP|ico|jpg|mp4|png|dll|hda|wav|max|hdr|fbx)$",
        r"(.*[\/\\]+|^)(UnrealEngine|Intermediate|DerivedDataCache|Binaries|ThirdParty|x86_64-unknown-linux-gnu|Cppcheck|bin)\/.*",
        r"(.*\/|^)(package-lock\.json|go\.sum|\.secrets\.baseline)$",
    ]
]


def do_exclude_file(file_path: str):
    for regex in FILE_EXCLUSION_REGEX:
        if regex.search(file_path.lower()):
            return True
    return False


depot_path_infos = {}


def depot_path_to_relative(p4: P4, depot_path: str):
    global depot_path_infos

    m = re.search(r"^(//[\w.-]*)/[\w.-]*", depot_path)
    if not m:
        return depot_path

    depot = m.group(1)
    possible_stream = m.group(0)

    if possible_stream not in depot_path_infos:
        depot_path_infos[possible_stream] = {
            "is_stream": False,
            "view_path": "",
            "depot": depot,
        }

        p4_streams = p4.run("streams", "-F", f"Stream={possible_stream}")
        if len(p4_streams) > 0:
            depot_path_infos[possible_stream]["is_stream"] = True

        p4_streams = p4.run("streams", "--viewmatch", depot_path)
        if len(p4_streams) > 0 and "ViewPath" in p4_streams[0]:
            view_path = p4_streams[0]["ViewPath"].rstrip("/...")
            depot_path_infos[possible_stream]["view_path"] = view_path

    if depot_path_infos[possible_stream]["is_stream"]:
        return depot_path[len(possible_stream) + 1 :]

    relative_path = depot_path[len(depot) + 1 :]
    if len(depot_path_infos[possible_stream]["view_path"]) > 0:
        return f"{depot_path_infos[possible_stream]['view_path']}/{relative_path}"
    return relative_path


def revert_last_shelve(p4, changelist):
    cl_description = p4.run("describe", "-s", "-S", changelist)
    if len(cl_description) == 0:
        print(f"Invalid changelist({changelist})")
        sys.exit(0)

    cl_description = cl_description[0]
    if "depotFile" not in cl_description or len(cl_description["depotFile"]) == 0:
        print(f"No file in depot for changelist({changelist})")
        sys.exit(0)

    # There is no simple way to only get the files modified/added by the current submit
    # So we are using the fstat headTime/headModTime to compare it to this `min_submit_time`
    min_submit_time = datetime.now() - timedelta(seconds=20)
    for depot_file in cl_description["depotFile"]:
        depo_path = f"{depot_file}@={changelist}"

        fstat = p4.run("fstat", "-Ob", depo_path)[0]
        head_mod_time = datetime.fromtimestamp(int(fstat["headModTime"]))
        head_time = datetime.fromtimestamp(int(fstat["headTime"]))
        submit_time = max(head_time, head_mod_time)

        if submit_time > min_submit_time:
            print(f"\ndelete {depot_file} shelve")
            print(f"- {submit_time} > {min_submit_time}")
            p4.run("shelve", "-f", "-d", "-Af", "-c", changelist, depot_file)


def get_secret_lines_from_file(file_io: NamedIO) -> Generator[List[str], None, None]:
    """equivalent of scan._get_lines_from_file but using a NamedIO as the file"""

    log.info(f"Checking file: {file_io.name}")

    try:
        lines = get_transformed_file(file_io)
        if not lines:
            lines = file_io.readlines()
    except UnicodeDecodeError:
        # We flat out ignore binary files
        return

    yield lines

    # If the above lines don't prove to be useful to the caller, try using eager transformers.
    file_io.seek(0)
    lines = get_transformed_file(file_io, use_eager_transformers=True)
    if not lines:
        return

    yield lines


def _scan_secret_file(secrets: SecretsCollection, file_io: NamedIO):
    """Scans a file to find Potential secrets."""

    for lines in get_secret_lines_from_file(cast(NamedIO, file_io)):
        for secret in _process_line_based_plugins(
            lines=list(enumerate(lines, 1)),
            filename=file_io.name,
        ):
            secrets[secret.filename].add(secret)


def scan_secret(secrets: SecretsCollection, relative_path: str, file_content):
    if not isinstance(file_content, str):  # don't scan binary files
        return

    file_io = io.StringIO(file_content)
    file_io.name = relative_path
    file_io.seek(0)
    _scan_secret_file(secrets, file_io)


def flatten_p4_print(p4_print_result: list):
    if len(p4_print_result) < 2 or type(p4_print_result[1]) != str:
        return ""
    return "".join(p4_print_result[1:])


if __name__ == "__main__":
    print("\n")  # to write script logs on a different line than the perforce trigger error message

    parser = argparse.ArgumentParser()
    parser.add_argument("user")
    parser.add_argument("client")
    parser.add_argument("changelist")
    parser.add_argument(
        "-g",
        "--exclude_group",
        help="Specifies an optional group to exclude for. Members of this group, or subgroups thereof will not be subject to this triggers.",
    )
    parser.add_argument(
        "--is-change-content",
        default=False,
        action="store_true",
        help="Use this if you use the trigger as a change-content.",
    )
    args = parser.parse_args()

    p4 = P4()
    p4.exception_level = 1  # don't raise on warnings
    # We are using "swarm" user instead of "buildbot" because it need admin right to delete shelved files
    p4.user = "swarm"
    p4.port = "ssl:perforce.darewise.com:1666"
    p4.connect()

    # Exit if the user belong to the exclude_group
    if args.exclude_group is not None:
        is_from_exclude_group = False
        user_groups = p4.run("groups", "-i", "-u", args.user)
        for user_group in user_groups:
            if "group" in user_group and user_group["group"] == args.exclude_group:
                is_from_exclude_group = True
        if is_from_exclude_group:
            print("User is from the exclude_group, exit trigger")
            sys.exit(0)

    secrets = SecretsCollection()
    with default_settings():
        cl_description = p4.run("describe", "-s", "-S", args.changelist)
        if len(cl_description) == 0:
            print(f"Invalid changelist({args.changelist})")
            sys.exit(1)

        cl_description = cl_description[0]
        depotFile = []
        if "depotFile" in cl_description and len(cl_description["depotFile"]) > 0:
            depotFile = cl_description["depotFile"]
        else:
            if args.is_change_content:
                cl_files = p4.run("files", f"//...@={ args.changelist}")
                for file in cl_files:
                    if "depotFile" not in file or len(file["depotFile"]) == 0:
                        continue
                    depotFile.append(file["depotFile"])
            else:
                print(f"No file in depot for changelist({args.changelist})")
                sys.exit(1)

        # scan changelist files
        for depot_file in depotFile:
            relative_path = depot_path_to_relative(p4, depot_file)

            if do_exclude_file(relative_path):
                continue

            file_content = flatten_p4_print(
                p4.run("print", "-q", f"{depot_file}@={args.changelist}")
            )
            if len(file_content) > 0:
                scan_secret(secrets, relative_path, file_content)

        # retrieve depot path
        if len(depot_path_infos) == 0:
            print("Failed to retrieve depot path")
        key = next(iter(depot_path_infos))
        depot_path = key
        if not depot_path_infos[key]["is_stream"]:
            depot_path = depot_path_infos[key]["depot"]

        # Try to get a baseline in the current changelist if updated by the user.
        baseline_content = p4.run(
            "print", "-q", f"{depot_path}/{SECRET_BASELINE}@={args.changelist}"
        )
        if len(baseline_content) > 0:
            args.baseline_filename = (
                f"{depot_path}/{SECRET_BASELINE}@={args.changelist}"
            )
        else:  # Else get the latest one from the depot
            baseline_content = p4.run("print", "-q", f"{depot_path}/{SECRET_BASELINE}")
            args.baseline_filename = f"{depot_path}/{SECRET_BASELINE}"

        # load baseline
        if len(baseline_content) == 0:
            args.baseline = SecretsCollection()
            args.baseline_filename = ""
        else:
            try:
                baseline_content = flatten_p4_print(baseline_content)
                if len(baseline_content) > 0:
                    loaded_baseline = cast(Dict[str, Any], json.loads(baseline_content))
                    args.baseline_version = loaded_baseline["version"]
                    args.baseline = baseline.load(
                        loaded_baseline, filename=args.baseline_filename
                    )
            except Exception as e:
                print(f"Invalid baseline: {args.baseline_filename}\n")
                print(e)
                sys.exit(1)

        # get baseline diff
        new_secrets = secrets
        if args.baseline:
            new_secrets = secrets - args.baseline

        if new_secrets:
            print("----------------------")
            if args.is_change_content:
                print("Please delete the followings secrets and retry to commit.")
            else:
                print("Please delete the followings secrets and retry to shelve.")
            print(
                "You can also review them using the `detect-secret/update_baseline.bat` script."
            )
            print(
                'Or use the command integrated with p4v, right-click on the cl and click on "Audit Secrets".'
            )
            print("----------------------")
            print("\n== Detected Secrets ==\n")
            pretty_print_diagnostics(new_secrets)
            print("\n======================")

            if not args.is_change_content:
                revert_last_shelve(p4, args.changelist)

            p4.disconnect()
            sys.exit(1)

        p4.disconnect()
