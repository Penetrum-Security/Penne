import zlib
import struct
import base64
import hashlib
import mimetypes

from penne.lib.settings import init


def verify_signature(sig):
    pass


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

    config = init()

    with open(filename, "rb") as file_:
        first_bytes = file_.read(byte_size)
        signature = generate_signature(first_bytes, os_filler, byte_size)


