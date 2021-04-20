#  Copyright (c) 2021-2025 Penetrum LLC <contact@penetrum.com> (MIT License)

import os
import sys
import json
import random
import hashlib
import logging
import zipfile

import pefile


log_format = "[ %(levelname)s ][ %(asctime)s ] %(message)s"
log = logging.getLogger(__name__)
sh = logging.StreamHandler()
log.setLevel(logging.DEBUG)
log.addHandler(sh)
log.handlers[0].setFormatter(logging.Formatter(fmt=log_format, datefmt="%d-%b-%y %H:%M:%S"))
HOME = os.getenv("PENNE_HOME", "{}/.penne".format(os.path.expanduser('~')))
CONFIG_FILE_PATH = "{}/penne.json".format(HOME)
DEFAULT_MOVE_DIRECTORY = "{}/backups".format(HOME)
VERSION_NUMBERS = "0.1"
VERSION_STRING = "dev" if VERSION_NUMBERS.count(".") > 2 else "stable"
SAYING = (
    "This AV is so good, it's pre-pasta-rous ...",
    "Hey Penne, don't you be a meanie!",
    "We did it fusilli reasons ...",
    "Penne for your thoughts?",
    "I ain't alfredo no malware!",
    "You wouldn't drezga a fancy bear, would you?",
    "If APT41 was a pasta, they'd be angel hair ...",
    "It's a farfalle drop from the top!",
    "Spaghetti (that's it just spaghetti)",
    "Penne-AV, stopping APT's since never ...",
    "It cost a pretty penne to make this AV!"
)
WELCOME_BANNER = """
\t__________                                         _________   ____
\t\\______   \\ ____   ____   ____   ____             /  _  \\   \\ /   /
\t |     ___// __ \\ /    \\ /    \\_/ __ \\   ______  /  /_\\  \\   Y   / 
\t |    |   \\  ___/|   |  \\   |  \\  ___/  /_____/ /    |    \\     /  
\t |____|    \\___  >___|  /___|  /\\___  >         \\____|__  /\\___/   
\t               \\/     \\/     \\/     \\/                  \\/  v{}({})\n
\n{}\n""".format(VERSION_NUMBERS, VERSION_STRING, random.choice(SAYING))


def download_default_config():
    import requests
    download_url = "https://penetrum.com/penne/penne.json"
    log.debug("downloading default config file from: {}".format(download_url))
    req = requests.get(download_url)
    return req.json()


def init():
    if not os.path.exists(HOME):
        config = download_default_config()
        os.makedirs(HOME)
        config_file_path = config['config']['penne_files']['config_file']
        folders = config['config']["penne_folders"]
        for key in folders.keys():
            log.debug("creating folder for: {}".format(key))
            if not os.path.exists(folders[key]):
                os.makedirs(folders[key].format(HOME))
        log.info("copying default config file to {}".format(config_file_path.format(HOME)))
        with open(CONFIG_FILE_PATH, "a+") as conf:
            json.dump(config, conf)
        return config
    else:
        with open(CONFIG_FILE_PATH) as data:
            return json.load(data)


def is_pe(filename):
    try:
        # easiest way to check is to use PEfile
        pefile.PE(filename)
        return True
    except pefile.PEFormatError:
        return False


def is_elf(filename):
    with open(filename, "rb") as f:
        # i've honestly never seen an ELF file that didn't start with this
        if f.read(4) == b"\x7ELF":
            return True
    return False


def is_android(filename):
    with open(filename, "rb") as f:
        # AndroidManifest.xml
        if b"AndroidManifest.xml" in f.read(4096):
            return True
    return False


def is_apple(filename):
    with open(filename, "rb") as f:
        # magic bytes in .app files
        if f.read(4) == b"\xcf\xfa\xed\xfe":
            return True
        f.seek(0)
        # .lprog is usually in .ipa files
        data = f.read(200)
        if b".app" in data and b"Payload" in data:
            return True
    return False


def is_doc(filename):
    with open(filename, "rb") as f:
        if f.read(4) in (b"%PDF", b"\x7b\x72\x74\x66", b"\xdb\xa5\x2d\x00", b"\x0d\x44\x4f\x43"):
            return True
        f.seek(0)
        if f.read(2) in (b"\xD0\xCF", b"\x14\x00", b"\x1d\x7d"):
            return True
    return False


def file_detection(filename):
    if is_pe(filename):
        os_filter = "Windows"
    elif is_elf(filename):
        os_filter = "Linux"
    elif is_android(filename):
        os_filter = "Android"
    elif is_apple(filename):
        os_filter = "Apple"
    elif is_doc(filename):
        os_filter = "Doc"
    else:
        os_filter = "Unknown"
    return os_filter


def random_string(length=30):
    import string

    retval = []
    acc = string.ascii_letters + string.digits
    for _ in range(length):
        retval.append(random.SystemRandom().choice(acc))
    return "".join(retval)


def verify_header(filename):
    with open(filename, "rb") as f:
        if f.read(7) == "\x70\x61\x73\x74\x61\x64\x62":
            return True
        return False


def beep():
    sys.stdout.write("\a")
    sys.stdout.flush()
    

def unzip_signatures(path):
    unzip_path = "{}/db/unzipped".format(HOME)
    with zipfile.ZipFile(path, "r") as ref:
        ref.extractall("{}/db/unzipped".format(HOME))
    return ["{}/{}".format(unzip_path, f) for f in os.listdir(unzip_path) if os.path.isfile("{}/{}".format(unzip_path, f))]


def get_hash(filename, hash_type="sha256"):
    h = hashlib.new(hash_type)
    with open(filename, "rb") as f:
        h.update(f.read())
    return h.hexdigest()
