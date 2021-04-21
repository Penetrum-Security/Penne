#  Copyright (c) 2021-2025 Penetrum LLC <contact@penetrum.com> (MIT License)

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os
import sys
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
    DEFAULT_MOVE_DIRECTORY
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


def do_quarn(f, detection_type, arch, detected_as):
    parts = pathlib.Path(f)
    filename = parts.name
    path = parts.parent
    quarantine_results = spicy_file(path, filename, detection_type, arch, detected_as)
    if quarantine_results["Success"]:
        log.info("file sent to cold storage at: {}".format(quarantine_results["ColdFile"]))


def check_signature(filename, do_beep=True):
    byte_sizes = (1024, 2048, 4096)
    with open(filename, "rb") as f:
        for b in byte_sizes:
            data = f.read(b)
            matches = pull_sig(data, b)
            if matches['Success']:
                termcolor.cprint(
                    "Match found:\nPath: {}\nOS Type: {}\nSHA-256: {}\nWarning Type: {}".format(
                        filename, matches['OS'], matches['Hash'], matches['Warning']
                    )
                )
                return True
    return False


def move_detected_file(source):
    file_dest_hash = get_hash(source)
    file_dest_path = "{}/{}".format(DEFAULT_MOVE_DIRECTORY, file_dest_hash)
    shutil.move(source, file_dest_path)
    try:
        os.chmod(file_dest_path, S_IREAD|S_IRGRP|S_IROTH)
    except:
        log.warn("unable to change file attributes to read only")
    return file_dest_path


def scan(start_dir, **kwargs):
    do_beep = kwargs.get("do_beep", True)
    display_only_infected = kwargs.get("display_only_infected", False)
    threads = kwargs.get("threads", 12)
    move_detected = kwargs.get("move_detected", False)

    walked_paths = walk(start_dir, threads=threads)

    for data in walked_paths:
        root, subs, files = data[0], data[1], data[-1]
        paths = [os.path.join(root, f) for f in files]
        for path in paths:
            if not display_only_infected:
                log.debug("scanning file: {}".format(path))
            results = check_signature(path, do_beep=do_beep)
            if results:
                if move_detected:
                    moved_to = move_detected_file(path)
                    log.info("file marked to be moved and moved to: {}".format(moved_to))
