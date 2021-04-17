import os
import sys

from penne.sigtools.sauce import make_signature
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
        print("scanning")
    if opts.sigtool:
        log.info("generating signature for passed file: {}".format(opts.filename))
        signature = make_signature(
            opts.filename, byte_size=opts.byteSize, os_filler=opts.osFiller, no_save_sig=opts.noSaveSig
        )
        print(signature)


if __name__ == "__main__":
    main()