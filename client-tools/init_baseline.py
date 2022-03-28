from P4 import P4
from detect_secrets import SecretsCollection
from detect_secrets.core import baseline
from detect_secrets.core.log import log
from detect_secrets.settings import default_settings
from detect_secrets_utils import scan_secret, depot_path_to_workspace_path, do_exclude_file, flatten_p4_print
import argparse
import json


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("client")
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        help="Verbose mode.",
    )
    args = parser.parse_args()
    if args.verbose:
        log.set_debug_level(args.verbose)

    p4 = P4()
    p4.exception_level = 1  # don't raise on warnings
    p4.client = args.client  # don't raise on warnings
    p4.connect()

    secrets = SecretsCollection()
    with default_settings():
        workspace_files = p4.run("have")
        for file in workspace_files:
            depot_file = file["depotFile"]
            relative_path = depot_path_to_workspace_path(p4, depot_file)
            if do_exclude_file(relative_path):
                continue

            file_content = flatten_p4_print(p4.run("print", "-q", f"{depot_file}"))
            if len(file_content) > 0:
                scan_secret(secrets, relative_path, file_content)

        print(json.dumps(baseline.format_for_output(secrets), indent=2))

    p4.disconnect()
