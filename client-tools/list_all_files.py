# list all files present in .secrets.baseline
from detect_secrets_utils import SECRET_BASELINE
from dw_python import file_utils
import json


def find_all_filenames(json_object):
    filenames = set()
    results_dict = json_object["results"]
    for secrets_in_file in results_dict.values():
        for secret in secrets_in_file:
            is_secret = True
            if "is_secret" in secret:
                is_secret = secret["is_secret"]

            if is_secret:
                filenames.add(secret["filename"])

    sorted_filenames = list(filenames)
    sorted_filenames.sort()
    return sorted_filenames


# main
if __name__ == "__main__":
    with open(file_utils.get_project_path(SECRET_BASELINE)) as f:
        object = json.load(f)
        filenames = find_all_filenames(object)
        print(*filenames, sep="\n")
