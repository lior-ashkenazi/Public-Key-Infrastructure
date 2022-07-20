from certification.config import CERT_NOT_BEFORE, CERT_NOT_AFTER, HASH_FUNC
from certification.certificate_cache import CertificateCache

from io import BytesIO

from OpenSSL import crypto

from certification.config import MAX_PATH_LEN

from certification.utils import write_pem, key_for_entity, get_random_serial_number


class CertificateAuthority:
    """
    Represents an authorised Certificate entity. That is, an entity in the PKI ecosystem that
    has a X509 certificate.
    """
    def __init__(self, ca_name, ca_cert=None, ca_key=None):
        self.ca_name = ca_name

        self.ca_cert_file = ""

        self.ca_cert, self.ca_key = ca_cert, ca_key

        self.certs_cache = CertificateCache()

        self.cert_not_before = CERT_NOT_BEFORE
        self.cert_not_after = CERT_NOT_AFTER

    def generate_root_ca_certificate(self, hash_func=HASH_FUNC):
        """
        Generates a certificate for the Root Certification Authority
        :param hash_func: a hash function, used for signing a certificate
        :return: certificate and its key
        """
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        cert = self._generate_certificate(self.ca_name)

        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.add_extensions([
            crypto.X509Extension(b"basicConstraints",
                                 True,
                                 b"CA:TRUE, pathlen:" + MAX_PATH_LEN),

            crypto.X509Extension(b"keyUsage",
                                 True,
                                 b"keyCertSign, cRLSign"),

            crypto.X509Extension(b"subjectKeyIdentifier",
                                 False,
                                 b"hash",
                                 subject=cert),
        ])
        cert.sign(key, hash_func)

        self.ca_cert, self.ca_key = cert, key

        buff = BytesIO()
        buff = write_pem(buff, self.ca_cert, self.ca_key)
        cert_content = buff.getvalue()

        self.certs_cache[self.ca_name] = cert_content

        self.ca_cert_file = key_for_entity(self.ca_name)

        return self.ca_cert, self.ca_key

    def generate_certificate_authority_entity(self, entity):
        """
        Generates a certificate for a Certificate Authority
        :param entity: a Certificate Authority
        :return: certificate and its key
        """
        utf8_entity = entity.encode('utf-8')
        # Key
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # CSR
        req = crypto.X509Req()
        req.get_subject().CN = utf8_entity
        req.set_pubkey(key)
        req.sign(key, HASH_FUNC)

        # Certificate
        cert = self._generate_certificate(utf8_entity)

        cert.set_issuer(self.ca_cert.get_subject())
        cert.set_pubkey(req.get_pubkey())

        cert.add_extensions([
            crypto.X509Extension(b"basicConstraints",
                                 True,
                                 b"CA:TRUE, pathlen:" + MAX_PATH_LEN),

            crypto.X509Extension(b"keyUsage",
                                 True,
                                 b"keyCertSign, cRLSign"),

            crypto.X509Extension(b"subjectKeyIdentifier",
                                 False,
                                 b"hash",
                                 subject=cert),
        ])

        cert.sign(self.ca_key, HASH_FUNC)

        buff = BytesIO()
        buff = write_pem(buff, cert, key)
        cert_content = buff.getvalue()

        self.certs_cache[entity] = cert_content

        return cert, key

    def generate_certificate_entity(self, entity):
        """
        Generates a certificate for a Certificate entity (*not* Certificate Authority)
        :param entity: a Certificate entity
        :return: a certificate and its key
        """
        utf8_entity = entity.encode('utf-8')
        # Key
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # CSR
        req = crypto.X509Req()
        req.get_subject().CN = utf8_entity
        req.set_pubkey(key)
        req.sign(key, HASH_FUNC)

        # Certificate
        cert = self._generate_certificate(utf8_entity)

        cert.set_issuer(self.ca_cert.get_subject())
        cert.set_pubkey(req.get_pubkey())

        cert.sign(self.ca_key, HASH_FUNC)

        buff = BytesIO()
        buff = write_pem(buff, cert, key)
        cert_content = buff.getvalue()

        self.certs_cache[entity] = cert_content

        return cert, key

    def _generate_certificate(self, cert_name):
        """
        Generates a x509 certificate
        :param cert_name: the certificate's owner name
        :return: x509 certificate
        """
        cert = crypto.X509()
        cert.set_serial_number(get_random_serial_number())
        cert.get_subject().CN = cert_name

        cert.set_version(2)
        cert.gmtime_adj_notBefore(self.cert_not_before)
        cert.gmtime_adj_notAfter(self.cert_not_after)
        return cert

    def get_certificate(self):
        """
        Returns certificate
        :return: certificate
        """
        return self.ca_cert
