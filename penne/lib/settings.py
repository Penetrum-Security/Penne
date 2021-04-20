#  Copyright (c) 2021-2025 Penetrum LLC <contact@penetrum.com> (MIT License)

import os
import sys
import json
import random
import hashlib
import logging
import zipfile

import pefile
import requests


log_format = "[ %(levelname)s ][ %(asctime)s ] %(message)s"
log = logging.getLogger(__name__)
sh = logging.StreamHandler()
log.setLevel(logging.DEBUG)
log.addHandler(sh)
log.handlers[0].setFormatter(logging.Formatter(fmt=log_format, datefmt="%d-%b-%y %H:%M:%S"))
HOME = os.getenv("PENNE_HOME", "{}/.penne".format(os.path.expanduser('~')))
CONFIG_FILE_PATH = "{}/penne.json".format(HOME)
DEFAULT_MOVE_DIRECTORY = "{}/backups".format(HOME)
HASHSUM_FILE = "{}/hashsums.txt".format(HOME)
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
    """
    download the default configuration file from the server
    """
    download_url = "https://penetrum.com/penne/penne.json"
    log.debug("downloading default config file from: {}".format(download_url))
    req = requests.get(download_url)
    return req.json()


def download_hashsums():
    """
    downloads the hashsum file in order to verify that that files downloaded from the server are correct
    """
    url = "https://penetrum.com/penne/hashsums.txt"
    req = requests.get(url)
    log.info("downloading hashsum file into: {}".format(HASHSUM_FILE))
    with open(HASHSUM_FILE, "a+") as f:
        f.write(req.text)
    return HASHSUM_FILE


def download_default_signatures():
    """
    downloads the signatures that are provided with Penne AV
    """
    config = init()
    urls = [
        "https://penetrum.com/penne/penne_signatures_honeypot.zip"
    ]
    for url in urls:
        log.info("downloading signature file from: {}".format(url))
        file_path = "{}/{}".format(config["config"]["penne_folders"]["database_folder"].format(HOME), url.split("/")[-1])
        if not os.path.exists(file_path):
            with requests.get(url, stream=True) as stream:
                stream.raise_for_status()
                with open(file_path, "wb") as file_:
                    for chunk in stream.iter_content(chunk_size=8192):
                        file_.write(chunk)
        else:
            log.warning("file exists, skipping")
    return [
        "{}/{}".format(config["config"]["penne_folders"]["database_folder"].format(HOME), f) for f in os.listdir(config["config"]["penne_folders"]["database_folder"].format(HOME)) \
        if os.path.isfile("{}/{}".format(config["config"]["penne_folders"]["database_folder"].format(HOME), f))
    ]


def verify_files(filepaths, hashsum_path):
    """
    check the files against the hashsums
    """
    bad, good = set(), set()
    for item in filepaths:
        if ".sqlite" not in item:
            with open(hashsum_path) as hashsums:
                for sum_ in hashsums.readlines():
                    data = sum_.split(" ")
                    hashsum = data[0]
                    downloaded_hash = get_hash(item)
                    if not hashsum == downloaded_hash:
                        log.error("file: {} hashsum ({}) does not match verified hashsum {}".format(
                            item, downloaded_hash, hashsum
                        ))
                        bad.add(item)
                    else:
                        good.add(item)
    return list(good), list(bad)


def initialize_database(config):
    from penne.quarantine.db_create import first_run, create_sig_table

    log.info("generating database")
    first_run()
    log.info("database generated successfully, generating signature tables")
    create_sig_table(config['config']['penne_folders']['unzipped_sigs'].format(HOME))
    log.info("signature tables generated successfully")


def init():
    """
    initialize the database and configuration file
    """

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
        download_hashsums()
        downloads_files = download_default_signatures()
        files = verify_files(downloads_files, HASHSUM_FILE)
        bad_files = files[1]
        for item in bad_files:
            log.warning("removing bad file: {}".format(item))
            os.remove(item)
        good_files = files[0]
        for item in good_files:
            unzip_signatures(item)
        initialize_database(config)
        return config
    else:
        with open(CONFIG_FILE_PATH) as data:
            return json.load(data)


def is_pe(filename):
    """
    verify the that file is a portable windows executable
    """
    try:
        # easiest way to check is to use PEfile
        pefile.PE(filename)
        return True
    except pefile.PEFormatError:
        return False


def is_elf(filename):
    """
    check if the file is a linux ELF file
    """
    with open(filename, "rb") as f:
        # i've honestly never seen an ELF file that didn't start with this
        if f.read(4) == b"\x7ELF":
            return True
    return False


def is_android(filename):
    """
    check if the files is an apk file or not
    """
    with open(filename, "rb") as f:
        # AndroidManifest.xml
        if b"AndroidManifest.xml" in f.read(4096):
            return True
    return False


def is_apple(filename):
    """
    check if the file is either a .app or a .ipa osX file
    """
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
    """
    check if the file is a doc file or not
    """
    with open(filename, "rb") as f:
        if f.read(4) in (b"%PDF", b"\x7b\x72\x74\x66", b"\xdb\xa5\x2d\x00", b"\x0d\x44\x4f\x43"):
            return True
        f.seek(0)
        if f.read(2) in (b"\xD0\xCF", b"\x14\x00", b"\x1d\x7d"):
            return True
    return False


def file_detection(filename):
    """
    detect the file type using the above checks
    """
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
    """
    generate a random string
    """
    import string

    retval = []
    acc = string.ascii_letters + string.digits
    for _ in range(length):
        retval.append(random.SystemRandom().choice(acc))
    return "".join(retval)


def verify_header(filename):
    """
    verify the signature file header (pastadb)
    """
    with open(filename, "rb") as f:
        if f.read(7) == "\x70\x61\x73\x74\x61\x64\x62":
            return True
        return False


def beep():
    """
    makes a beep on most systems
    """
    sys.stdout.write("\a")
    sys.stdout.flush()
    

def unzip_signatures(path):
    """
    unzip the signatures to the correct path:
    """
    log.info("unzipping signatures from path: {}".format(path))
    unzip_path = "{}/db/unzipped".format(HOME)
    with zipfile.ZipFile(path, "r") as ref:
        ref.extractall("{}/db/unzipped".format(HOME))
    return ["{}/{}".format(unzip_path, f) for f in os.listdir(unzip_path) if os.path.isfile("{}/{}".format(unzip_path, f))]


def get_hash(filename, hash_type="sha256"):
    """
    get a files hash checksum
    """
    h = hashlib.new(hash_type)
    with open(filename, "rb") as f:
        h.update(f.read())
    return h.hexdigest()
