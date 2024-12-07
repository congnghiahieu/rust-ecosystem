import glob
import hashlib
import json
import multiprocessing
import os
import random
import shutil
import sqlite3
import sys
from pprint import pprint as print
from typing import Callable, Optional
from urllib.parse import urlparse

import pandas as pd
import requests

CSV_INPUT = "dataset/data/vulnerabilities/fix_commits.csv"


def traverse_csv(output_file: str, select_func: Optional[Callable[..., bool]] = None):
    df = pd.read_csv(CSV_INPUT)
    headers = df.columns.tolist()
    data = []

    for index, row in df.iterrows():
        if select_func is not None and not select_func(row):
            continue

        obj = {}

        for header in headers:
            obj[header] = row[header]

        obj["commit_url"] = os.path.join(obj["repo_url"], "commit", obj["hash"])
        obj["parent_url"] = os.path.join(obj["repo_url"], "commit", obj["parents"])

        data.append(obj)

    print(f"{len(data)} fix commits found.")
    json.dump(data, open(output_file, "w"), indent=2)


def connect_and_traverse_db(db_path: str, table_names: list[tuple[str, str]] = []):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    def conver_to_json(table_name: str, output_file: str):
        cursor.execute(f"SELECT * FROM {table_name}")
        rows = cursor.fetchall()
        columns = [description[0] for description in cursor.description]
        data = [dict(zip(columns, row)) for row in rows]
        with open(output_file, "w") as json_file:
            json.dump(data, json_file, indent=2)

    for table_name in table_names:
        conver_to_json(table_name[0], table_name[1])

    conn.close()


def file_change_num_files_1_no_dups():
    hash_num_files_1 = list(
        set(map(lambda x: x["hash"], json.load(open("fix_commits_num_files_1.json"))))
    )

    hash_lens = list(set(map(lambda x: len(x), hash_num_files_1)))
    json.dump(hash_lens, open("hash_lens.json", "w"), indent=2)

    file_change_num_files_1 = list(
        filter(
            lambda x: x["hash"] in hash_num_files_1, json.load(open("file_change.json"))
        )
    )
    print(len(file_change_num_files_1))
    print(len(hash_num_files_1))

    file_change_num_files_1_hashes = list(
        set(map(lambda x: x["hash"], file_change_num_files_1))
    )
    print(len(file_change_num_files_1_hashes))
    print(len(hash_num_files_1))

    temp_set = set()
    dups = []
    no_dup_data = []
    for obj in file_change_num_files_1:
        if obj["hash"] in temp_set:
            dups.append(obj["hash"])
        else:
            temp_set.add(obj["hash"])
            no_dup_data.append(obj)

    print(len(dups))
    print(len(no_dup_data))
    json.dump(dups, open("dups.json", "w"), indent=2)
    json.dump(no_dup_data, open("file_change_num_files_1_no_dups.json", "w"), indent=2)


def get_diff():
    file_change_num_files_1_no_dups = json.load(
        open("file_change_num_files_1_no_dups.json")
    )

    diff_txt_dir = "diff.txt"
    os.makedirs(diff_txt_dir, exist_ok=True)
    for obj in file_change_num_files_1_no_dups:
        filepath = f"{diff_txt_dir}/{obj['hash']}.txt"
        with open(filepath, "w") as diff_file:
            diff_file.write(obj["diff"])

    diff_json_dir = "diff.json"
    os.makedirs(diff_json_dir, exist_ok=True)
    for obj in file_change_num_files_1_no_dups:
        filepath = f"{diff_json_dir}/{obj['hash']}.json"
        with open(filepath, "w") as diff_file:
            diff_file.write(obj["diff_parsed"])


def merge_data():
    fix_commits = json.load(open("fix_commits_num_files_1.json"))
    file_changes = json.load(open("file_change_num_files_1_no_dups.json"))

    assert len(fix_commits) == len(file_changes)

    "https://github.com/lettre/lettre/blob/8bfc20506cc5e098fe6eb3d1cafe3bea791215ce/lettre/src/smtp/client/mod.rs"

    data = []
    for fix_commit in fix_commits:
        for file_change in file_changes:
            if fix_commit["hash"] == file_change["hash"]:
                repo_url = fix_commit["repo_url"]
                repo_blob_url = os.path.join(repo_url, "blob")
                old_url = os.path.join(
                    repo_blob_url,
                    fix_commit["parents"],
                    file_change["old_path"],
                )
                new_url = os.path.join(
                    repo_blob_url,
                    fix_commit["hash"],
                    file_change["new_path"],
                )
                raw_content_url = fix_commit["repo_url"].replace(
                    "https://github.com/", "https://raw.githubusercontent.com/"
                )
                raw_old_url = os.path.join(
                    raw_content_url,
                    fix_commit["parents"],
                    file_change["old_path"],
                )
                raw_new_url = os.path.join(
                    raw_content_url,
                    fix_commit["hash"],
                    file_change["new_path"],
                )

                obj = {
                    "cve_id": fix_commit["cve_id"],
                    "repo_url": repo_url,
                    "parents": fix_commit["parents"],
                    "hash": fix_commit["hash"],
                    "parent_url": fix_commit["parent_url"],
                    "commit_url": fix_commit["commit_url"],
                    "file_change_id": file_change["file_change_id"],
                    "path_change": file_change["old_path"] != file_change["new_path"],
                    "old_path": file_change["old_path"],
                    "new_path": file_change["new_path"],
                    "old_url": old_url,
                    "new_url": new_url,
                    "raw_old_url": raw_old_url,
                    "raw_new_url": raw_new_url,
                }
                data.append(obj)
                break

    json.dump(data, open("merge.json", "w"), indent=2)


def join_table():
    conn = sqlite3.connect("CVEfixes.db")
    cursor = conn.cursor()

    cursor.execute(
        f"SELECT cve_id, parents, commits.hash, repo_url, file_change_id, old_path, new_path FROM commits INNER JOIN file_change ON commits.hash = file_change.hash WHERE LENGTH(commits.hash) >= 39 GROUP BY commits.hash, old_path"
    )
    # GROUP BY commits.hash, old_path
    rows = cursor.fetchall()
    columns = [description[0] for description in cursor.description]
    data = [dict(zip(columns, row)) for row in rows]

    count_set = set()
    domain_set = set()

    for obj in data:
        # https://gitlab.com/KonradBorowski/array-macro/-/raw/a9d5b42ca96365159102f9d18d71be343f6c42e9/src/lib.rs
        # https://gitlab.com/KonradBorowski/array-macro/-/blob/a9d5b42ca96365159102f9d18d71be343f6c42e9/src/lib.rs
        # https://gitlab.com/KonradBorowski/array-macro/-/commit/a9d5b42ca96365159102f9d18d71be343f6c42e9

        # https://raw.githubusercontent.com/lettre/lettre/d930c42d5069e344a9dfa84ebe4b60bf3b11ac64/lettre/src/smtp/client/mod.rs
        # "https://github.com/lettre/lettre/blob/8bfc20506cc5e098fe6eb3d1cafe3bea791215ce/lettre/src/smtp/client/mod.rs"
        # https://github.com/lettre/lettre/commit/8bfc20506cc5e098fe6eb3d1cafe3bea791215ce

        # parse_result = urlparse(obj["repo_url"])
        # domain_set.add(parse_result.netloc)
        # count_set.add(f"{obj["hash"]}{obj["old_path"]}")

        urlparse_result = urlparse(obj["repo_url"])

        match urlparse_result.netloc:
            case "github.com":
                repo_blob_url = os.path.join(obj["repo_url"], "blob")
                raw_content_url = obj["repo_url"].replace(
                    "https://github.com/", "https://raw.githubusercontent.com/"
                )
                parent_url = os.path.join(obj["repo_url"], "commit", obj["parents"])
                commit_url = os.path.join(obj["repo_url"], "commit", obj["hash"])
                pass
            case "gitlab.com":
                repo_blob_url = os.path.join(obj["repo_url"], "-", "blob")
                raw_content_url = os.path.join(obj["repo_url"], "-", "raw")
                parent_url = os.path.join(
                    obj["repo_url"], "-", "commit", obj["parents"]
                )
                commit_url = os.path.join(obj["repo_url"], "-", "commit", obj["hash"])
                pass
            case _:
                repo_blob_url = ""
                raw_content_url = ""
                parent_url = ""
                commit_url = ""
                pass

        obj["parent_url"] = parent_url
        obj["commit_url"] = commit_url
        obj["old_url"] = os.path.join(
            repo_blob_url,
            obj["parents"],
            obj["old_path"],
        )
        obj["new_url"] = os.path.join(
            repo_blob_url,
            obj["hash"],
            obj["new_path"],
        )
        obj["raw_old_url"] = os.path.join(
            raw_content_url,
            obj["parents"],
            obj["old_path"],
        )
        obj["raw_new_url"] = os.path.join(
            raw_content_url,
            obj["hash"],
            obj["new_path"],
        )

    print(len(data))
    print(len(count_set))

    # with open("domain.json", "w") as json_file:
    #     json.dump(list(domain_set), json_file, indent=2)

    with open("join.json", "w") as json_file:
        json.dump(data, json_file, indent=2)

    # def conver_to_json(table_name: str, output_file: str):
    #     cursor.execute(f"SELECT * FROM {table_name}")
    #     rows = cursor.fetchall()
    #     columns = [description[0] for description in cursor.description]
    #     data = [dict(zip(columns, row)) for row in rows]
    #     with open(output_file, "w") as json_file:
    #         json.dump(data, json_file, indent=2)

    conn.close()


def dowload_code_files():
    def download_file(url: str, dest: str):
        response = requests.get(url)
        with open(dest, "wb") as file:
            file.write(response.content)

    dest_dir = "downloads.python.100"
    os.makedirs(dest_dir, exist_ok=True)
    with open("merge.json") as file:
        data = json.load(file)
        processes = []

        for obj in data:
            url = obj["raw_old_url"]
            dest = os.path.join(dest_dir, f"{obj['parents']}.rs")

            process = multiprocessing.Process(target=download_file, args=(url, dest))
            processes.append(process)
            process.start()

        for process in processes:
            process.join()


def get_join_dataset():
    join_data = json.load(open("join.json"))

    manager = multiprocessing.Manager()
    safe_shared_list = manager.list()
    failed_url_list = manager.list()
    safe_target0_counter = multiprocessing.Value("i", 0)  # Shared
    safe_target1_counter = multiprocessing.Value("i", 0)  # Shared

    processes = []

    def create_one_record(data_obj: dict[str, str], url: str):
        response = requests.get(url)

        if not response.ok:
            failed_url_list.append(
                {
                    "url": url,
                    "status_code": response.status_code,
                    "reason": response.reason,
                }
            )
            return

        if data_obj["target"] == 0:
            with safe_target0_counter.get_lock():  # Ensure atomic operation
                safe_target0_counter.value += 1
        elif data_obj["target"] == 1:
            with safe_target1_counter.get_lock():  # Ensure atomic operation
                safe_target1_counter.value += 1

        safe_shared_list.append(
            {
                **data_obj,
                "func": response.text,
            }
        )

    for obj in join_data:
        parent_commit_process = multiprocessing.Process(
            target=create_one_record,
            args=(
                {
                    "project": obj["repo_url"].split("/")[-1],
                    "target": 1,
                    "commit_id": obj["parents"],
                    "file_path": obj["old_path"],
                },
                obj["raw_old_url"],
            ),
        )
        fix_commit_process = multiprocessing.Process(
            target=create_one_record,
            args=(
                {
                    "project": obj["repo_url"].split("/")[-1],
                    "target": 0,
                    "commit_id": obj["hash"],
                    "file_path": obj["new_path"],
                },
                obj["raw_new_url"],
            ),
        )

        processes.append(parent_commit_process)
        processes.append(fix_commit_process)
        parent_commit_process.start()
        fix_commit_process.start()

    for process in processes:
        process.join()

    print(f"Total bug rust files: {len(safe_shared_list)}")
    print(f"Total target 0 rust files: {safe_target0_counter.value}")
    print(f"Total target 1 rust files: {safe_target1_counter.value}")

    with open("dataset.join.json", "w") as json_file:
        json.dump(list(safe_shared_list), json_file, indent=2)
    with open("failed.join.json", "w") as json_file:
        json.dump(list(failed_url_list), json_file, indent=2)


get_join_dataset()


def get_bug_dataset(code_dir: str, outfile: str):
    merge_data = json.load(open("merge.json"))
    data = []

    code_dir_hashes = set(map(lambda x: x.removesuffix(".rs"), os.listdir(code_dir)))

    for merge_obj in merge_data:
        if merge_obj["parents"] not in code_dir_hashes:
            continue

        obj = {}

        old_file_path = os.path.join(code_dir, f"{merge_obj['parents']}.rs")
        project_name = merge_obj["repo_url"].split("/")[-1]

        obj["project"] = project_name
        obj["target"] = 1
        obj["commit_id"] = merge_obj["parents"]
        obj["func"] = open(old_file_path).read()

        data.append(obj)

    print(f"Total bug rust files: {len(data)}")

    json.dump(data, open(outfile, "w"), indent=2)


def get_safe_dataset(code_dir: str, outfile: str):
    data = []

    for filename in os.listdir(code_dir):
        obj = {}

        obj["project"] = ""
        obj["target"] = 0
        obj["commit_id"] = filename.removesuffix(".rs")
        obj["func"] = open(os.path.join(code_dir, filename)).read()

        data.append(obj)

    print(f"Total safe rust files: {len(data)}")

    json.dump(data, open(outfile, "w"), indent=2)


def count_line(folder_path: str):
    sum_loc = 0
    count_file = 0

    for file in os.listdir(folder_path):
        with open(f"{folder_path}/{file}") as f:
            count_file += 1
            sum_loc += len(f.readlines())

    print(f"Total files in {folder_path}: {count_file}")
    print(f"Total lines in {folder_path}: {sum_loc}")


def copy_apart(src_folder: str, dst_folder: str, percent: float):
    if not (0 <= percent <= 1):
        raise ValueError("Percent must be between 0 and 1")
    os.makedirs(dst_folder, exist_ok=True)

    file_list = os.listdir(src_folder)
    origin_amount = len(file_list)
    discounted_amount = int(origin_amount * percent)
    file_list = file_list[:discounted_amount]

    for file in file_list:
        shutil.copyfile(f"{src_folder}/{file}", f"{dst_folder}/{file}")

    print(
        f"Copy {discounted_amount}/{origin_amount} files from {src_folder} to {dst_folder}"
    )


def generate_random_commit_hash():
    random_data = os.urandom(10)
    return hashlib.sha1(random_data).hexdigest()


def get_safe_rust_files(percent: float):
    if not (0 <= percent <= 1):
        raise ValueError("Percent must be between 0 and 1")

    SAFE_RUST_SRC_DIR = "/home/hieucien/Workspace/rust-parser/tests/projects"
    SAFE_RUST_OUT_DIR = f"./safe.rust.{int(percent * 100)}"
    shutil.rmtree(SAFE_RUST_OUT_DIR, ignore_errors=True)
    os.makedirs(SAFE_RUST_OUT_DIR, exist_ok=True)

    count = 0
    file_list = [
        filepath
        for filepath in glob.glob(f"{SAFE_RUST_SRC_DIR}/**/*.rs", recursive=True)
        if os.path.isfile(filepath)
    ]

    for filepath in file_list:
        ran_num = random.choice(range(1, 101))
        if ran_num > percent * 100:
            continue

        with open(filepath) as f:
            loc = len(f.readlines())
            if loc <= 0:
                continue

            count += 1
            shutil.copyfile(
                filepath, f"{SAFE_RUST_OUT_DIR}/{generate_random_commit_hash()}.rs"
            )

    print(f"Total safe rust files: {count}/{len(file_list)}")


def combile_bug_and_safe_dataset(safe_dataset: str, bug_dataset: str, output_file: str):
    safe_data: list = json.load(open(safe_dataset))
    bug_data: list = json.load(open(bug_dataset))

    data = [*safe_data, *bug_data]
    random.shuffle(data)

    print(f"Total safe + bug files: {len(data)}")

    json.dump(data, open(output_file, "w"), indent=2)


if __name__ == "__main__":
    # count_line("downloads.python.100")
    # count_line("joern.ffmpeg")

    # count_line("downloads.python.100")
    # count_line("downloads.python.50")
    # count_line("downloads.python.70")

    # copy_apart("downloads.python.100", "downloads.python.50", 0.5)
    # copy_apart("downloads.python.100", "downloads.python.70", 0.7)

    # get_bug_dataset("downloads.python.100", "bug.rust.100.json")
    # get_bug_dataset("downloads.python.50", "bug.rust.50.json")
    # get_bug_dataset("downloads.python.70", "bug.rust.70.json")

    # PERCENT = 0.02
    # OUTNAME = f"safe.rust.{int(PERCENT * 100)}"
    # get_safe_rust_files(PERCENT)
    # get_safe_dataset(OUTNAME, f"{OUTNAME}.json")

    # combile_bug_and_safe_dataset(
    #     "safe.rust.2.json", "bug.rust.100.json", "dataset.rust.json"
    # )

    # merge_data()
    # get_diff()

    # get_project_data()

    def get_csv_data():
        select_func = None
        output_file = "fix_commits.json"

        if len(sys.argv) == 2 and sys.argv[1] == "1":
            select_func = lambda row: row["num_files"] == 1 and len(row["hash"]) in [
                39,
                40,
            ]
            output_file = "fix_commits_num_files_1.json"

        traverse_csv(output_file, select_func)

    def get_sqlite_data():
        db_path = "CVEfixes.db"
        table_names = [
            ("file_change", "file_change.json"),
            ("commits", "commits.json"),
        ]
        connect_and_traverse_db(db_path, table_names)
