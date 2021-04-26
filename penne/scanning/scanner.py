#  Copyright (c) 2021-2025 Penetrum LLC <contact@penetrum.com> (MIT License)

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os
import sys
import json
import shutil
import pathlib
import binascii
import threading
import platform

from stat import (
    S_IREAD,
    S_IRGRP,
    S_IROTH
)

import termcolor

from penne.lib.settings import (
    log,
    beep,
    get_hash,
    DEFAULT_MOVE_DIRECTORY,
    COMPLETED_RESULTS,
    FINISHED_FILES_JSON_LIST,
    random_string,
    pause
)
from penne.quarantine.noodler import spicy_file
from penne.quarantine.db_create import pull_sig


def walk(top, threads=12):
    if not os.path.isdir(top):
        yield None
    lock = threading.Lock()
    on_input = threading.Condition(lock)
    on_output = threading.Condition(lock)
    state = {'tasks': 1}
    paths = [top]
    output = []

    def worker():
        while True:
            with lock:
                while True:
                    if not state['tasks']:
                        output.append(None)
                        on_output.notify()
                        return
                    if not paths:
                        on_input.wait()
                        continue
                    path = paths.pop()
                    break
            try:
                dirs = []
                files = []
                for item in sorted(os.listdir(path)):
                    subpath = os.path.join(path, item)
                    if os.path.isdir(subpath):
                        dirs.append(item)
                        with lock:
                            state['tasks'] += 1
                            paths.append(subpath)
                            on_input.notify()
                    else:
                        files.append(item)
                with lock:
                    output.append((path, dirs, files))
                    on_output.notify()
            except OSError as e:
                print(e, file=sys.stderr)
            finally:
                with lock:
                    state['tasks'] -= 1
                    if not state['tasks']:
                        on_input.notifyAll()

    workers = [threading.Thread(target=worker,
                                name="fastio.walk %d %s" % (i, top))
               for i in range(threads)]
    for w in workers:
        w.start()
    while threads or output:
        with lock:
            while not output:
                on_output.wait()
            item = output.pop()
        if item:
            yield item
        else:
            threads -= 1


def do_yara_rule_check(filename, api_key):
    # TODO:/
    pass


def do_quarn(f, detection_type, arch, detected_as):
    parts = pathlib.Path(f)
    filename = parts.name
    path = parts.parent
    quarantine_results = spicy_file(path, filename, detection_type, arch, detected_as)
    if quarantine_results["Success"]:
        log.info("file sent to cold storage at: {}".format(quarantine_results["ColdFile"]))
    else:
        log.warn("we were unable to send file to cold storage")


def check_signature(filename, do_beep=True):
    byte_sizes = (1024, 2048, 4096)
    with open(filename, "rb") as f:
        for b in byte_sizes:
            data = binascii.hexlify(f.read(b)).decode()
            matches = pull_sig(data, b)
            if matches['Success']:
                if do_beep:
                    beep()
                termcolor.cprint(
                    "\nMatch found:\nPath: {}\nOS Type: {}\nSHA-256: {}\nWarning Type: {}\n".format(
                        filename, matches['OS'], matches['Hash'], matches['Warning']
                    )
                )
                return True, matches["Warning"]
    return False, None


def move_detected_file(source, detection, detected_as="EVIL AF"):
    architecture = platform.architecture()
    file_dest_hash = get_hash(source)
    file_dest_path = "{}/{}_{}".format(DEFAULT_MOVE_DIRECTORY, file_dest_hash, random_string(length=30))
    try:
        shutil.move(source, file_dest_path)
    except:
        log.warning("unable to move file, going to copy it instead and change originals permissions to read only")
        shutil.copy(source, file_dest_path)
        try:
            os.chmod(source, S_IREAD | S_IRGRP | S_IROTH)
        except:
            log.error("unable to change original source files permissions ({})".format(source))
    try:
        os.chmod(file_dest_path, S_IREAD | S_IRGRP | S_IROTH)
    except:
        log.warn("unable to change file attributes to read only")
    do_quarn(source, detection, architecture, detected_as)
    return file_dest_path


def finish_scan():

    def percent(part, whole):
        try:
            return str(100 * part/whole)[0:5]
        except:
            return 100 * part/whole

    def show_opts():
        retval = ""
        if len(COMPLETED_RESULTS["infected_files"]) != 0:
            retval += "to see the list of infected files run: penneav --infected\n"
        if len(COMPLETED_RESULTS["moved_files"]) != 0:
            retval += "to see the files that were moved run: penneav --moved\n"
        if len(COMPLETED_RESULTS["unable_to_scan"]) != 0:
            retval += "to see files that were unable to be scanned run: penneav --unable\n"
        if len(COMPLETED_RESULTS["unable_to_cold_store"]) != 0:
            retval += "to see the files that failed cold storage run: penneav --failed\n"
        return retval

    if not os.path.exists(FINISHED_FILES_JSON_LIST):
        attribute = "a+"
    else:
        attribute = "w"
    percentage = percent(COMPLETED_RESULTS["total_scanned"], COMPLETED_RESULTS["total_found"])
    with open(FINISHED_FILES_JSON_LIST, attribute) as res:
        data = {
            "infected": COMPLETED_RESULTS["infected_files"],
            "unable": COMPLETED_RESULTS["unable_to_scan"],
            "moved": COMPLETED_RESULTS["moved_files"],
            "failed": COMPLETED_RESULTS["unable_to_cold_store"]
        }
        json.dump(data, res)
    log.info("scanning finished")
    termcolor.cprint(
        "\n\nSCAN RESULTS:\n"
        "{}\n"
        "FINISHED SCANNING: {}\n"
        "FILES MOVED: {}\n"
        "UNABLE TO BE SCANNED: {}\n"
        "INFECTED FILES FOUND: {}\n"
        "FAILED COLD STORAGE: {}\n"
        "TOTAL AMOUNT OF FILES FOUND DURING SCAN: {}\n"
        "PERCENT THAT FINISHED SCANNING: {}%"
        "\n{}\n"
        "\n"
        "{}".format(
            "-" * 47,
            COMPLETED_RESULTS["total_scanned"],
            len(COMPLETED_RESULTS["moved_files"]),
            len(COMPLETED_RESULTS["unable_to_scan"]),
            len(COMPLETED_RESULTS["infected_files"]),
            len(COMPLETED_RESULTS["unable_to_cold_store"]),
            COMPLETED_RESULTS["total_found"],
            percentage,
            "-" * 47, show_opts()
        ), "green", attrs=["bold"]
    )


def scan(start_dir, **kwargs):
    do_beep = kwargs.get("do_beep", True)
    display_only_infected = kwargs.get("display_only_infected", False)
    threads = kwargs.get("threads", 12)
    move_detected = kwargs.get("move_detected", False)
    follow_syms = kwargs.get("follow_sym", False)
    ignored_dirs = kwargs.get("ignored_dirs", [])
    ignored_files = kwargs.get("ignored_files", [])

    walked_paths = walk(start_dir, threads=threads)

    for data in walked_paths:
        root, subs, files = data[0], data[1], data[-1]
        paths = [
            os.path.join(root, f) for f in files if f not in ignored_files or d not in os.path.join(root, f) for d in ignored_dirs
        ]
        for path in paths:
            try:
                COMPLETED_RESULTS["total_found"] += 1
                try:
                    if not display_only_infected:
                        log.debug("scanning file: {}".format(path))
                    if follow_syms:
                        if os.path.islink(path):
                            if not display_only_infected:
                                log.info("found symlink and following")
                            path = os.path.realpath(path)
                            if not display_only_infected:
                                log.debug("real path from symlink: {}".format(path))
                    results = check_signature(path, do_beep=do_beep)
                    if results[0]:
                        COMPLETED_RESULTS["infected_files"].append(path)
                        if move_detected:
                            moved_to = move_detected_file(path, results[1])
                            log.info("file marked to be moved and moved to: {}".format(moved_to))
                            COMPLETED_RESULTS["moved_files"].append(path)
                    COMPLETED_RESULTS["total_scanned"] += 1
                except Exception:
                    log.error("unable to finish file scanning on filename: {}".format(path))
                    COMPLETED_RESULTS["unable_to_scan"].append(path)
            except KeyboardInterrupt:
                results = pause(filename=path)
                if results:
                    continue
                else:
                    pass
