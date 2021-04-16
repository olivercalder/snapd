#!/usr/bin/python3

import argparse
import glob
import os
import sys
import yaml
import yamlordereddictloader

SUPPORTED_KEYS = [
    'summary',
    'details',
    'backends',
    'systems',
    'manual',
    'priority',
    'warn-timeout',
    'kill-timeout',
    'environment',
    'prepare',
    'restore',
    'debug',
    'execute'
    ]
MANDATORY_KEYS = [
    'summary',
    'execute'
]


def check_mandatory_keys(task_keys):
    findings=[]
    for key in MANDATORY_KEYS:
        if key not in task_keys:
            findings.append("Key '{}' is mandatory".format(key))

    return findings


def check_keys_order(task_keys):
    last_index=-1
    last_key=''
    findings=[]

    for curr_key in task_keys:
        try:
            curr_index = SUPPORTED_KEYS.index(curr_key)
            if curr_index <= last_index:
                findings.append("Keys '{}' and '{}' do not follow the desired order: {}".format(last_key, curr_key, SUPPORTED_KEYS))

            last_index = curr_index
            last_key = curr_key

        except ValueError as err:
            findings.append("key '{}' not included in the suported keys: {}".format(curr_key, SUPPORTED_KEYS))

    return findings


def check_task(filepath):
    if not os.path.isfile(filepath):
        print("Checks failed for task {}".format(filepath))
        print(' - The path is not a file')
        return False

    filemap=dict()
    with open(filepath, "r") as task:
        filemap = yaml.load(task, Loader=yamlordereddictloader.Loader)

    findings = check_keys_order(filemap.keys())
    findings.extend(check_mandatory_keys(filemap.keys()))
    if findings:
        print("Checks failed for task {}".format(filepath))
        for finding in findings:
            print(' - ' + finding)
        return False

    return True


def check_dir(directory):
    if not os.path.isdir(directory):
        print("Checks failed for directory {}".format(directory))
        print(' - The path is not a directory')
        return False

    status = True
    for file in glob.glob(os.path.join(directory, "**/task.yaml"), recursive=True):
        if not check_task(file):
            status = False

    return status


def _make_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--directory', help="path to the directory to check recursively")
    return parser


def main():
    parser = _make_parser()
    args = parser.parse_args()

    if args.directory:
        sys.exit(not check_dir(args.directory))


if __name__ == "__main__":
    main()
