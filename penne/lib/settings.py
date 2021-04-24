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
from penne.lib.spinner import Spinner

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
FINISHED_FILES_JSON_LIST = "{}/finished.json".format(HOME)
COMPLETED_RESULTS = {
    "unable_to_scan": [],
    "moved_files": [],
    "total_scanned": 0,
    "infected_files": []
}
WHITELISTED_HASHES = (
    # empty files
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    # .git files
    "0223497a0b8b033aa58a3a521b8629869386cf7ab0e2f101963d328aa62193f7",
    "1f74d5e9292979b573ebd59741d46cb93ff391acdd083d340b94370753d92437",
    "3ee1726fce7169faf7b5f1c0ff6dc229deab5a2642b005ce8e603c3f4e05e162",
    "522eb45b6bb3dfb00c53baf876c3d5d6e8e6c3a70a5cbd491f990c450bef6624",
    "6671fe83b7a07c8932ee89164d1f2793b2318058eb8b98dc5c06ee0a5a3b0ec1",
    "73480ff46d8753638f8475a2fdddf9399a26ef7f0be5eb6292cd20aa765ea043",
    "81765af2daef323061dcbc5e61fc16481cb74b3bac9ad8a174b186523586f6c5",
    "85ab6c163d43a17ea9cf7788308bca1466f1b0a8d1cc92e26e9bf63da4062aee",
    "85c88a914219203c1a21ff96f0f7fb02871c474f05c0f01f648c6aa5f9732c47",
    "9154a73a556e2d16655f4d635191e9c0581a34e4dee973b6107be9f5db987bc6",
    "a4c3d2b9c7bb3fd8d1441c31bd4ee71a595d66b44fcf49ddb310252320169989",
    "e15c5b469ea3e0a695bea6f2c82bcf8e62821074939ddd85b77e0007ff165475",
    "f445f03f6621591dacda807ec0deb292ca40d8bb9905f09e3317b5d5775fe959",
    "f6f2b945f6c411b02ba3da9c7ace88dcf71b6af65ba2e0d89aa82900042b5a10",
    "164c5fa8067facf1a43f09ce3d0e35ebf53a7f5723ecbf15a8667cfc53c26f6c",
    # cargo "ok" file (rust file that just says "ok" in a binary format)
    "2689367b205c16ce32ed4200942b8b8b1e262dfc70d9bc9fbc77c49699a4f1df"
)
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
        "https://penetrum.com/penne/penne_signatures_honeypot.zip",
        "https://penetrum.com/penne/penne_penetrum_samples.zip",
        "https://penetrum.com/penne/apt_malware_1.zip",
        "https://penetrum.com/penne/apt_malware_2.zip"
    ]
    for url in urls:
        log.info("downloading signature file from: {}".format(url))
        file_path = "{}/{}".format(config["config"]["penne_folders"]["database_folder"].format(HOME),
                                   url.split("/")[-1])
        if not os.path.exists(file_path):
            with requests.get(url, stream=True) as stream:
                stream.raise_for_status()
                with open(file_path, "wb") as file_:
                    for chunk in stream.iter_content(chunk_size=8192):
                        file_.write(chunk)
        else:
            log.warning("file exists, skipping")
    return [
        "{}/{}".format(config["config"]["penne_folders"]["database_folder"].format(HOME), f) for f in
        os.listdir(config["config"]["penne_folders"]["database_folder"].format(HOME)) \
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
                downloaded_hash = get_hash(item)
                if downloaded_hash not in hashsums.read():
                    log.error("file: {} hashsum ({}) does not match verified hashsums".format(item, downloaded_hash))
                    bad.add(item)
                else:
                    good.add(item)
    return list(good), list(bad)


def rinse_pasta(folder_path):
    with Spinner():
        for item in os.listdir(folder_path):
            try:
                os.remove("{}/{}".format(folder_path, item))
            except:
                pass


def initialize_database(config):
    from penne.quarantine.db_create import first_run, create_sig_table

    log.info("generating database")
    try:
        results = first_run()
        if results["Success"]:
            log.info("database generated successfully, generating signature tables")
        else:
            log.warning(
                "Database was not successfully generated. Please double check as to why, or report it as a bug.\n"
                "{0}\n{1}".format(results["TraceBack"], results["Error"]))

        result = create_sig_table(config['config']['penne_folders']['unzipped_sigs'].format(HOME))
        if result["Success"]:
            log.info(
                "signature tables generated successfully total signatures in DB: {}".format(
                    result['Total Sigs in DB']))
        else:
            log.warning("Could not create signature table, please double check the db was created, or report as a bug.")
    except TypeError:
        log.warning("Could not confirm that the DB was created properly. Please manually verify.")


def init():
    """
    initialize the database and configuration file
    """

    if not os.path.exists(HOME):
        config = download_default_config()
        try:
            os.makedirs(HOME)
        except FileExistsError:
            log.warning("Appears as though the files already exist.")
        config_file_path = config['config']['penne_files']['config_file']
        folders = config['config']["penne_folders"]
        for key in folders.keys():
            log.debug("creating folder for: {}".format(key))
            try:
                if not os.path.exists(folders[key]):
                    os.makedirs(folders[key].format(HOME))
            except FileExistsError as e:
                log.warning("Appears as though a file was already created/exists: {}".format(e))
                continue
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
        with Spinner():
            for item in good_files:
                unzip_signatures(item)
        with Spinner():
            initialize_database(config)
        log.info("cleaning up pasta files")
        rinse_pasta(config["config"]["penne_folders"]["database_folder"].format(HOME) + "/unzipped")
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
        if f.read(4) == b"\x7fELF":
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
    return ["{}/{}".format(unzip_path, f) for f in os.listdir(unzip_path) if
            os.path.isfile("{}/{}".format(unzip_path, f))]


def get_hash(filename, hash_type="sha256"):
    """
    get a files hash checksum
    """
    h = hashlib.new(hash_type)
    with open(filename, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def list_files(**kwargs):
    list_moved = kwargs.get("list_moved", False)
    list_infected = kwargs.get("list_infected", False)
    list_unable = kwargs.get("list_unable", False)

    s_found = "list of {} during last scan:"
    s_not_found = "no files {} during last scan"
    do_exit = False

    if os.path.exists(FINISHED_FILES_JSON_LIST):
        with open(FINISHED_FILES_JSON_LIST, "r") as f:
            data = json.load(f)
            if list_moved:
                do_exit = True
                log.info(s_found.format("files moved"))
                if len(data["moved"]) != 0:
                    for item in data["moved"]:
                        print(item)
                else:
                    log.info(s_not_found.format("moved"))
            if list_infected:
                do_exit = True
                log.info(s_found.format("infected files found"))
                if len(data["infected"]) != 0:
                    for item in data["infected"]:
                        print(item)
                else:
                    log.info(s_not_found.format("found to be infected"))
            if list_unable:
                do_exit = True
                log.info(s_found.format("files unable to be processed"))
                if len(data["unable"]) != 0:
                    for item in data["unable"]:
                        print(item)
                else:
                    log.info(s_not_found.format("were unable to scanned"))
    if do_exit:
        exit(1)
    else:
        pass