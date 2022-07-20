import os


CERT_NOT_BEFORE = 0

CERT_NOT_AFTER = 3 * 365 * 24 * 60 * 60

BASE_DIR = os.path.dirname(os.path.realpath(__file__))

CERTS_DIR = os.path.join(BASE_DIR, "certificates")

HASH_FUNC = "sha256"

MAX_PATH_LEN = b"10"

DATE_FORMAT_ASN1 = "%y%m%d%H%M%SZ"

