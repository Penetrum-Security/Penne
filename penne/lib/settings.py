import os
import json
import random
import logging

log_format = "[ %(levelname)s ][ %(asctime)s ] %(message)s"
log = logging.getLogger(__name__)
sh = logging.StreamHandler()
log.setLevel(logging.DEBUG)
log.addHandler(sh)
log.handlers[0].setFormatter(logging.Formatter(fmt=log_format, datefmt="%d-%b-%y %H:%M:%S"))

HOME = os.getenv("PENNE_HOME", "{}/.penne".format(os.path.expanduser('~')))
CONFIG_FILE_PATH = "{}/penne.json".format(HOME)
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


def file_detection(filename):
    log.info("attempting to detect file type")
    return "Windows"