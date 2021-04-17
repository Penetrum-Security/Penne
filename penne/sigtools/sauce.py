import re
import zlib
import struct
import base64
import hashlib

from penne.lib.settings import (
    init,
    log,
    file_detection
)


def verify_signature(sig):
    filler_acceptable = ("windows", "linux", "apple", "android", "unknown")
    sha_identifier = re.compile("^[a-fA-F0-9]{64}$")
    penne_sig_identifier = re.compile("^[A-Za-z1-9]{2,5}(=)?$")
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
    if not penne_sig_identifier.match(pieces[2]):
        log.warn("penne signature was not able to be matched, is it base64 encoded?")
        return False
    if not sha_identifier.match(pieces[-1]):
        log.warn("unable to match the checksum, is it type sha256?")
        return False
    return True


def generate_signature(sig, filler, bytes_size):
    sha256 = hashlib.sha256()
    sha256.update(sig)
    hashsum = sha256.hexdigest()
    sig = sig.encode("utf8") if not isinstance(sig, bytes) else sig
    result = base64.b64encode(struct.pack(">H", (zlib.crc32(sig) & 0xffff)))
    return "{}:{}:{}:{}".format(filler, bytes_size, result, hashsum)


def make_signature(filename, **kwargs):
    verify = kwargs.get("verify", True)
    byte_size = kwargs.get("byte_size", 1024)
    os_filler = kwargs.get("os_filler", "Unknown")

    if os_filler == "DETECT":
        os_filler = file_detection(filename)

    # todo:// save?
    config = init()

    with open(filename, "rb") as file_:
        first_bytes = file_.read(byte_size)
        signature = generate_signature(first_bytes, os_filler, byte_size)
        if verify:
            res = verify_signature(signature)
            if res:
                log.info("signature verified successfully")
                return signature
            else:
                log.error("unable to verify signature")
                return None
        else:
            log.warn("skipping signature verification")
            return signature



