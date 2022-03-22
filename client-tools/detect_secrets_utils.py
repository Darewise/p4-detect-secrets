""" utils functions to manage secret detection
"""

from datetime import datetime, timedelta
from detect_secrets import SecretsCollection, exceptions
from detect_secrets.core import baseline
from detect_secrets.core.log import log
from detect_secrets.core.scan import _process_line_based_plugins
from detect_secrets.main import handle_audit_action
from detect_secrets.transformers import get_transformed_file
from detect_secrets.types import NamedIO
from P4 import P4
from typing import Generator, cast, List, Optional
import argparse
import io
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


def partial_merge(self, new_results: "SecretsCollection", scanned_files: Optional[List[str]]) -> None:
    """Merge a SecretsCollection with a scan made on a partial list of files.
    It works like SecretsCollection.merge, but keep the files not scanned using the provided scanned_files argument.
    Useful to update the baseline on a set of files without rescanning the whole depot.
    """

    for filename in scanned_files:
        if filename not in new_results.files:
            # Delete file that has no more secrets detected
            if filename in self.files:
                self.data.pop(filename, None)
            continue

        # Add new files
        if filename not in self.files:
            self.data[filename] = new_results.data[filename]
            continue

        # This allows us to obtain the same secret, by accessing the hash.
        mapping = {secret: secret for secret in self.data[filename]}

        # merge filename secrets
        for new_secret in new_results.data[filename]:
            if new_secret not in mapping:
                self.data[filename].add(new_secret)
                continue

            # Only override if there's no newer value.
            if new_secret.is_secret is not None:
                mapping[new_secret].is_secret = new_secret.is_secret

            # If the old value is false, it won't make a difference.
            if new_secret.is_verified:
                mapping[new_secret].is_verified = new_secret.is_verified


SecretsCollection.partial_merge = partial_merge


def audit():
    handle_audit_action(argparse.Namespace(verbose=None, filename=[".secrets.baseline"], diff=False, stats=False, json=False))


def get_client_stream(p4: P4, client: str):
    client_info = p4.run("client", "-o", client)
    if len(client_info) == 0 or "Stream" not in client_info[0]:
        print(f"Can't find client stream for client: {client}\nclient_info: {client_info}")
        sys.exit(1)
    stream = client_info[0]["Stream"]
    while True:
        stream_info = p4.run("stream", "-o", stream)
        if len(stream_info) == 0 or "Parent" not in stream_info[0] or stream_info[0]["Parent"] == "none":
            break
        stream = stream_info[0]["Parent"]
    return stream


depot_path_infos = {}


def depot_path_to_relative(p4: P4, depot_path: str):
    global depot_path_infos

    m = re.search(r"^(//[\w.-]*)/[\w.-]*", depot_path)
    if not m:
        return depot_path

    depot = m.group(1)
    possible_stream = m.group(0)

    if possible_stream not in depot_path_infos:
        depot_path_infos[possible_stream] = {"is_stream": False, "view_path": "", "depot": depot}

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


def load_baseline(args: argparse.ArgumentParser):
    try:
        loaded_baseline = baseline.load_from_file(args.baseline_filename)
    except exceptions.UnableToReadBaselineError:
        raise argparse.ArgumentTypeError("Unable to read baseline.")

    try:
        args.baseline_version = loaded_baseline["version"]
        args.baseline = baseline.load(loaded_baseline, filename=args.baseline_filename)
    except KeyError:
        raise argparse.ArgumentTypeError("Invalid baseline.")


def flatten_p4_print(p4_print_result: list):
    if len(p4_print_result) < 2 or type(p4_print_result[1]) != str:
        return ""
    return "".join(p4_print_result[1:])
