#  Copyright (c) 2021-2025 Penetrum LLC <contact@penetrum.com> (MIT License)

import sys
import argparse

from penne.lib.settings import (
    log,
    WELCOME_BANNER
)


class Parser(argparse.ArgumentParser):

    def __init__(self):
        super(Parser, self).__init__()

    @staticmethod
    def optparse():
        parser = argparse.ArgumentParser(
            prog="penneav",
            usage="{} -[s|i|g] -[args]".format(__name__),
            description="PenneAV is a cross compatible opensource Antivirus solution"
        )
        required = parser.add_argument_group("Required Arguments")
        required.add_argument(
            "-s", "--scan", action="store_true", default=False, help="Begin scanning on a provided directory",
            dest="scanner"
        )
        required.add_argument(
            "-i", "--init", action="store_true", default=False, dest="initialize",
            help="Initialize the database and configuration. Can only be run once"
        )
        required.add_argument(
            "-g", "--sigtool", action="store_true", default=False, dest="sigtool",
            help="Generate a Penne signature for a passed filename or directory of files"
        )
        scanning = parser.add_argument_group("Scanning Arguments")
        scanning.add_argument(
            "-M", "--move", action="store_true", default=False, dest="moveFiles",
            help="Move files as they're detected (BE CAREFUL WITH THIS)"
        )
        scanning.add_argument(
            "--no-beep", action="store_true", default=False, dest="turnBeepOff",
            help="Pass to disable the beep upon discovering an infected file"
        )
        scanning.add_argument(
            "-I", "--only-infected", action="store_true", default=False, dest="displayOnlyInfected",
            help="Pass to display only infected files that are discovered (disable verbosity)"
        )
        scanning.add_argument(
            "-t", "--threads", type=int, dest="threadNum", default=12,
            help="Pass an amount of threads to run the scanner with (*MAX=30)"
        )
        scanning.add_argument(
            "-d", "--dir", dest="startDir", default=".",
            help="Pass to start scanning on this directory (default is your current directory)"
        )
        sigtool = parser.add_argument_group("Sigtool Arguments")
        sigtool.add_argument(
            "-w", "--warning", dest="warnType", default="DETECT",
            help="Pass your own warning type by default Penne will try to detect the warning type with a default of "
                 "a generic unwanted warning", choices=["unwanted", "malware"]
        )
        sigtool.add_argument(
            "-b", "--byte-size", type=int, default=1024, dest="byteSize", choices=[1024, 2048, 4096],
            help="Pass the byte size you want to read from the file for signature generation"
        )
        sigtool.add_argument(
            "-V", "--verify", dest="verify", default=True, action="store_true",
            help="If you don't want to verify your signature, pass this switch to turn off the optimization"
        )
        sigtool.add_argument(
            "-o", "--os-filler", default="DETECT", dest="osFiller", metavar="OS-TYPE",
            help="Pass what operating system this support this signature should use. If nothing is passed Penne "
                 "will try to detect the file"
        )
        sigtool.add_argument(
            "--no-save", action="store_true", default=False, dest="noSaveSig",
            help="Pass this flag to output the signature as raw text instead of saving to a database file under "
                 "PENNE_HOME/db/user_defined"
        )
        misc = parser.add_argument_group("Misc Arguments")
        misc.add_argument("-f", "--filename", dest="filename", help="Pass a filename or directory to use", default=None)
        misc.add_argument("--unable", dest="listUnable", action="store_true", default=False, help=argparse.SUPPRESS)
        misc.add_argument("--moved", dest="listMoved", action="store_true", default=False, help=argparse.SUPPRESS)
        misc.add_argument("--infected", dest="listInfected", default=False, action="store_true", help=argparse.SUPPRESS)
        return parser.parse_args()


def verify_args(opts):
    """
    verify that the arguments are acceptable to be run together
    """
    special_opts = (opts.initialize, opts.sigtool, opts.scanner)
    list_opts = (opts.listUnable, opts.listMoved, opts.listInfected)
    if any(list_opts):
        return
    special_opts_flags = ["-g/--sigtool", "-i/--initialize", "-s/--scan"]
    total = 0
    for opt in special_opts:
        if opt:
            total += 1
    if total == 0:
        log.error("must pass a required argument to begin, required arguments can be found in the help menu (penne -h)")
        sys.exit(1)
    if total != 1:
        log.error(
            "can only pass a total of 1 of the required arguments at a time ({}). You have passed a total of {}. "
            "Please verify your arguments and rerun Penne.".format(
                ", ".join(special_opts_flags), total
            )
        )
        sys.exit(1)
    if opts.sigtool and opts.filename is None:
        log.error("must supply a filename with sigtool to generate the signature")
        sys.exit(1)
    if opts.threadNum > 30:
        log.warning("max amount of threads is 30 (you passed {}), defaulting down to 30 threads".format(opts.threadNum))
        opts.threadNum = 30
    print(WELCOME_BANNER)
