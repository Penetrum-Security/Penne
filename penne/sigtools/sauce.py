import base64
import mimetypes

from penne.lib.settings import init


def guess_file_type(filename):
    return mimetypes.guess_type(filename)[0].split("/")[1].upper()


def verify_signature(sig):
    pass


def make_signature(filename, **kwargs):
    verify = kwargs.get("verify", True)
    byte_size = kwargs.get("byte_size", 1024)
    encode_signature = kwargs.get("encode_signature", True)

    config = init()

    with open(filename, "rb") as file_:
        first_1024_bytes = file_.read(byte_size)

