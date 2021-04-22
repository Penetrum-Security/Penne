#  Copyright (c) 2021-2025 Penetrum LLC <contact@penetrum.com> (MIT License)

import os
import sys

from penne.sigtools.sauce import make_signature
from penne.scanning.scanner import scan
from penne.lib.cmd import (
    Parser,
    verify_args
)
from penne.lib.settings import (
    init,
    log,
    HOME
)


def main():
    opts = Parser().optparse()
    verify_args(opts)

    if opts.initialize:
        if os.path.exists(HOME):
            log.error("already initialized")
            sys.exit(1)
        log.info("initializing the database")
        init()
        log.info("done, rerun Penne")
        sys.exit(1)
    if opts.scanner:
        log.info("starting scan on directory: {}".format(
            opts.startDir if opts.startDir != "." else "current directory"
        ))
        scan(
            opts.startDir,
            display_only_infected=opts.displayOnlyInfected,
            threads=opts.threadNum,
            move_detected=opts.moveFiles
        )
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


if __name__ == "__main__":
    try:
        main()
    except:
        log.warning("program is not intialized, starting initialization")
        init()
