from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os
import sys
import pathlib
import binascii
import threading
import platform

import termcolor

from penne.sigtools.sauce import generate_signature
from penne.lib.settings import (
    log,
    beep
)
from penne.quarantine.noodler import spicy_file


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
    print( spicy_file(path, filename, detection_type, arch, detected_as) )


def check_signature(filename, loaded_signatures, do_beep=True, move_files=False):
    for signature in loaded_signatures:
        with open(signature, "r") as sig:
            _, os_type, bytes_read, flag_type, signature, sha_hash = sig.read().split(":")
            with open(filename, "rb") as to_scan:
                data = to_scan.read(int(bytes_read))
                if data == binascii.unhexlify(signature):
                    if do_beep:
                        beep()
                    termcolor.cprint(
                        "Match found\nPath: {}\nOS type: {}\nSHA-256: {}\nWarning type: {}".format(
                            filename, os_type, sha_hash, flag_type.upper()
                        ), "yellow"
                    )
                    if move_files:
                        arch = platform.architecture()
                        do_quarn(filename, flag_type, arch, "EVIL_AF")


def scan(start_dir, signatures, **kwargs):
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
            check_signature(path, signatures, do_beep=do_beep, move_files=move_detected)
