import os

import datetime

from certification.config import CERTS_DIR, DATE_FORMAT_ASN1

from OpenSSL import crypto
from OpenSSL.SSL import FILETYPE_PEM

import random


def key_for_entity(entity_name):
    """
    Returns a Certificate entity's certificate file path
    :param entity_name: the name of the Certificate entity; an ID
    :return: the path of the Certificate entity's certificate
    """
    return os.path.join(CERTS_DIR, entity_name) + '.pem'


def key_for_entity_crl(entity_name):
    """
    Returns a Certificate entity's CRL file
    :param entity_name: the name of the Certificate entity; an ID
    :return: the path of the Certificate entity's CRL file
    """
    return os.path.join(CERTS_DIR, entity_name) + '.crl.pem'


def write_pem(buff, cert, key):
    """
    Writes a certificate and its key to a buffer, into a buffer - PEM type
    :param buff: a bytes buffer
    :param cert: a X509 certificate
    :param key: a key to a certificate
    :return: the buffer
    """
    buff.write(crypto.dump_privatekey(FILETYPE_PEM, key))
    buff.write(crypto.dump_certificate(FILETYPE_PEM, cert))
    return buff


def read_pem(buff):
    """
    Read a certificate and its key from a buffer - PEM type
    :param buff: a bytes buffer
    :param cert: a X509 certificate
    :param key: a key to a certificate
    :return: a x509 certificate and its key
    """
    cert = crypto.load_certificate(FILETYPE_PEM, buff.read())
    buff.seek(0)
    key = crypto.load_privatekey(FILETYPE_PEM, buff.read())
    return cert, key


def get_random_serial_number():
    """
    :return: A random serial number
    """
    return random.randint(0, (2 ** 64) - 1)


def get_current_time(date_str=DATE_FORMAT_ASN1):
    """
    Returns the current time (necessary for generation of certificates)
    :param date_str: the requested string format for the dates
    :return: a string with current date
    """
    now = datetime.datetime.now()
    return now.strftime(date_str).encode()


def int_to_hex(num):
    """
    Converts a decimal number to hexidecimal number
    :param num: an int with decimal number
    :return: a hexidecimal number
    """
    return format(num, "02x")


def hex_to_int(hex_str):
    """
    Converts a hexidecimal number to decimal number
    :param num: a hexidecimal number in a string
    :return: a decimal number
    """
    return int(hex_str, 16)
