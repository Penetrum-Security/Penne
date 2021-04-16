import os
import json
import shutil
import random
import logging

log = logging.getLogger(__name__)

HOME = os.getenv("PENNE_HOME", f"{os.path.expanduser('~')}/.penne")
CONFIG_FILE_PATH = f"{HOME}/penne.json"
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


def init():
    if not os.path.exists(HOME):
        os.makedirs(HOME)
        with open("../default/penne.json") as default:
            config = json.load(default)
            config_file_path = config['penne_files']['config_file']
            folders = config["penne_folders"]
            for key in folders.keys():
                log.debug(f"creating folder for: {key}")
                if not os.path.exists(folders[key]):
                    os.makedirs(format(folders[key]))
            log.info(f"copying default config file to {config_file_path}")
            shutil.copy("../default/penne.json", config_file_path)
            return config
    else:
        with open(CONFIG_FILE_PATH) as data:
            return json.load(data)
