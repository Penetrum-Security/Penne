import re
import hashlib

from penne.lib.settings import (
    init,
    log,
    file_detection,
    random_string,
    HOME
)


def verify_signature(sig):
    filler_acceptable = ("windows", "linux", "apple", "android", "unknown")
    sha_identifier = re.compile("^[a-fA-F0-9]{64}$")
    pieces = sig.split(":")
    log.info("verifying signature")
    if pieces[0].lower() not in filler_acceptable:
        log.warn("signature OS filler is not in the acceptable list ({})".format(", ".join(list(filler_acceptable))))
        return False
    try:
        int(pieces[1])
    except:
        log.warn("signature bytes is not of type int")
        return False
    if not sha_identifier.match(pieces[-1]):
        log.warn("unable to match the checksum, is it type sha256?")
        return False
    return True


def save_sig(sig, conf):
    filename = "{}/{}.pasta".format(conf["config"]["penne_folders"]["user_defined"].format(HOME), random_string())
    log.info("saving signature to user defined database under: {}".format(filename))
    with open(filename, "wb") as file_:
        file_.write("\x70\x61\x73\x74\x61\x64\x62:{}".format(sig))


def generate_signature(sig, filler, bytes_size, warn_type="unwanted"):
    sha256 = hashlib.sha256()
    sha256.update(sig)
    hashsum = sha256.hexdigest()
    sig = sig.encode("utf8") if not isinstance(sig, bytes) else sig
    result = sig.encode("hex")
    return "{}:{}:{}:{}:{}".format(filler, bytes_size, warn_type, result, hashsum)


def make_signature(filename, **kwargs):
    verify = kwargs.get("verify", True)
    byte_size = kwargs.get("byte_size", 1024)
    os_filler = kwargs.get("os_filler", "Unknown")
    no_save_sig = kwargs.get("no_save_sig", False)

    if os_filler == "DETECT":
        os_filler = file_detection(filename)

    config = init()

    with open(filename, "rb") as file_:
        first_bytes = file_.read(byte_size)
        signature = generate_signature(first_bytes, os_filler, byte_size)
        if verify:
            res = verify_signature(signature)
            if res:
                log.info("signature verified successfully")
                if no_save_sig:
                    log.warn("not saving signature to database file, instead outputting as raw text")
                    return signature
                else:
                    return save_sig(signature, config)
            else:
                log.error("unable to verify signature")
                return None
        else:
            log.warn("skipping signature verification")
            return signature
