import threading

from certification.config import CERTS_DIR

from certification.utils import key_for_entity


class CertificateCache:
    """
    Cache for certificates
    """
    def __init__(self, certs_dir=CERTS_DIR):
        self._lock = threading.Lock()
        self.certs_dir = certs_dir

    def __setitem__(self, entity, cert_str):
        file_name = key_for_entity(entity)
        with self._lock:
            with open(file_name, 'wb') as f:
                f.write(cert_str)

    def get(self, entity):
        """
        Getter for Certificate entity's certificate
        :param entity: a Certificate entity
        :return: a certificate
        """
        file_name = key_for_entity(entity)
        try:
            with open(file_name, 'rb') as f:
                return f.read()
        except:
            return b''
