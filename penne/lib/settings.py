import os
import json
import shutil
import logging

log = logging.getLogger(__name__)

HOME = os.getenv("PENNE_HOME", f"{os.path.expanduser('~')}/.penne")
CONFIG_FILE_PATH = f"{HOME}/penne.json"
VERSION_NUMBERS = "0.1"
VERSION_STRING = "dev" if VERSION_NUMBERS.count(".") < 2 else "stable"
WELCOME_BANNER = rf"""
\t__________                                         _________   ____
\t\______   \ ____   ____   ____   ____             /  _  \   \ /   /
\t |     ___// __ \ /    \ /    \_/ __ \   ______  /  /_\  \   Y   / 
\t |    |   \  ___/|   |  \   |  \  ___/  /_____/ /    |    \     /  
\t |____|    \___  >___|  /___|  /\___  >         \____|__  /\___/   
\t               \/     \/     \/     \/                  \/  v{VERSION_NUMBERS}({VERSION_STRING})\n\n"""


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
