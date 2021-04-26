#  Copyright (c) 2021-2025 Penetrum LLC <contact@penetrum.com> (MIT License)

import os
import sys
import datetime

from penne.sigtools.sauce import make_signature
from penne.lib.cmd import (
    Parser,
    verify_args
)
from penne.lib.settings import (
    init,
    log,
    HOME,
    list_files,
    close
)


def main():
    opts = Parser().optparse()
    verify_args(opts)

    list_files(
        list_moved=opts.listMoved,
        list_infected=opts.listInfected,
        list_unable=opts.listUnable,
        list_failed=opts.listFailed
    )

    print("\nstarting PenneAV at: {}\n".format(datetime.datetime.now().strftime("%m/%d/%Y %H:%M:%S")))

    if opts.initialize:
        if os.path.exists(HOME):
            log.error("already initialized")
            sys.exit(1)
        log.info("initializing the database")
        init()
        log.info("done, rerun Penne")
        sys.exit(1)
    if opts.scanner:
        # because we're extremely smart, we try to load the file before it exists
        # we spent about an hour on stream trying to figure out why we're so smart
        # until we realized that we tried to import something without the file
        # GENIUS
        from penne.scanning.scanner import scan, finish_scan
        log.info("starting scan on directory: {}".format(
            opts.startDir if opts.startDir != "." else "current directory"
        ))
        scan(
            opts.startDir,
            display_only_infected=opts.displayOnlyInfected,
            threads=opts.threadNum,
            move_detected=opts.moveFiles,
            follow_sym=opts.followSym,
            ignored_dirs=opts.ignoreDirs,
            ignored_files=opts.ignoreFiles,
            do_beep=opts.turnBeepOff
        )
        finish_scan()
    if opts.sigtool:
        if os.path.isdir(opts.filename):
            files = ["{}/{}".format(opts.filename, f) for f in os.listdir(opts.filename)]
            log.info("generating a total of {} signature(s) for files in {}".format(len(files), opts.filename))
        else:
            log.info("generating a signature for passed file: {}".format(opts.filename))
            files = [opts.filename]
        for f in files:
            if not os.path.isdir(f):
                make_signature(
                    f, byte_size=opts.byteSize, os_filler=opts.osFiller, no_save_sig=opts.noSaveSig,
                    warn_type=opts.warnType
                )
    close()


if __name__ == "__main__":
    main()