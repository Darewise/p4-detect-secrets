"""run this to updtate secrets
"""

from dw_python import p4_utils, file_utils
from detect_secrets import SecretsCollection
from detect_secrets.core import baseline
from detect_secrets.settings import default_settings
from detect_secrets_utils import (
    audit,
    scan_secret,
    depot_path_to_workspace_path,
    do_exclude_file,
    flatten_p4_print,
    SECRET_BASELINE,
    depot_path_infos,
)
from typing import Dict, Any, cast
import argparse
import json
import os.path
import sys
from pathlib import Path

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("changelist")
    args = parser.parse_args()

    p4 = p4_utils.connect(allow_user_prompt=True, search_workspace=True)

    # Retrieve changelist client
    cl_change = p4.run("change", "-o", args.changelist)
    if len(cl_change) == 0:
        print(f"Invalid changelist({args.changelist})")
        sys.exit(0)
    client = cl_change[0]["Client"]

    # Check that we use the same client as the CL
    if client != p4.client:
        p4.disconnect
        p4.client = client
        p4.connect()
    if client != p4.client:
        print(f"Please connect to the same client as the Changelist owner.\ncl_client({client}) != your_client({p4.client})")
        sys.exit(0)

    # move to the workspace root directory
    client_infos = p4.run("client", "-o", client)
    if len(client_infos) > 0 and "Root" in client_infos[0]:
        os.chdir(client_infos[0]["Root"])

    secrets = SecretsCollection()
    with default_settings():
        cl_description = p4.run("describe", "-s", args.changelist)
        if len(cl_description) == 0:
            print(f"Invalid changelist({args.changelist})")
            sys.exit(0)

        cl_description = cl_description[0]
        if "depotFile" not in cl_description or len(cl_description["depotFile"]) == 0:
            print(f"No file in depot for changelist({args.changelist})")
            sys.exit(0)

        scanned_files = []
        for depot_file in cl_description["depotFile"]:
            relative_path = depot_path_to_workspace_path(p4, depot_file)

            if do_exclude_file(relative_path):
                continue

            print(f"scan {relative_path}...")
            scanned_files.append(relative_path)
            if os.path.exists(relative_path):
                with open(relative_path, "r", errors="ignore") as fd:
                    file_content = fd.read()
                    scan_secret(secrets, relative_path, file_content)
        print("")

        # load baseline
        args.baseline = SecretsCollection()
        args.baseline_filename = ""
        baseline_content = ""

        # retrieve depot path
        if len(depot_path_infos) == 0:
            print("Failed to retrieve depot path")
        key = next(iter(depot_path_infos))
        depot_path = key
        if not depot_path_infos[key]["is_stream"]:
            depot_path = depot_path_infos[key]["depot"]

        # create baseline if not found
        is_baseline_created = len(p4.run("files", f"{depot_path}/{SECRET_BASELINE}")) > 0
        if not is_baseline_created:
            secret_baseline_absolute = Path(SECRET_BASELINE).absolute()
            file_utils.write_file_if_different(secret_baseline_absolute, "")
            p4.run("add", "-d", secret_baseline_absolute)

        is_baseline_opened = len(p4.run("opened", f"{depot_path}/{SECRET_BASELINE}")) > 0
        if is_baseline_opened:
            with open(SECRET_BASELINE, "r") as fd:
                baseline_content = fd.read()
                args.baseline_filename = SECRET_BASELINE
        else:
            baseline_content = flatten_p4_print(p4.run("print", "-q", f"{depot_path}/{SECRET_BASELINE}"))
            if len(baseline_content) > 0:
                args.baseline_filename = f"{depot_path}/{SECRET_BASELINE}"

        if len(baseline_content) > 0:
            try:
                loaded_baseline = cast(Dict[str, Any], json.loads(baseline_content))
                args.baseline_version = loaded_baseline["version"]
                args.baseline = baseline.load(loaded_baseline, filename=args.baseline_filename)
            except Exception as e:
                print(f"Invalid baseline: {args.baseline_filename}\n")
                raise e

        # get baseline diff
        new_secrets = secrets
        if args.baseline:
            new_secrets = secrets - args.baseline

        if new_secrets:
            args.baseline.partial_merge(new_secrets, scanned_files)

            # checkout or move SECRET_BASELINE to the current baseline
            if is_baseline_opened:
                reopen = p4.run("reopen", "-c", args.changelist, f"{depot_path}/{SECRET_BASELINE}")
                print(f"p4 reopen: {reopen}")
            else:
                edit = p4.run("edit", "-c", args.changelist, f"{depot_path}/{SECRET_BASELINE}")
                print(f"p4 edit: {edit}")

            with open(SECRET_BASELINE, "w") as fd:
                fd.write(json.dumps(baseline.format_for_output(args.baseline), indent=2))
                print(f"Secret Baseline successfully updated ({SECRET_BASELINE})")
        else:
            print("Nothing to add to the current baseline.")
        p4.disconnect()

        if new_secrets:
            input("Press enter to Audit secrets.")
            audit()
