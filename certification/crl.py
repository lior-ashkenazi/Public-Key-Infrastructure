from OpenSSL import crypto
from OpenSSL.SSL import FILETYPE_PEM
from OpenSSL.crypto import X509Store, X509StoreFlags, X509StoreContext, X509StoreContextError
from OpenSSL.crypto import Error

from io import BytesIO
from certification.utils import key_for_entity_crl, get_current_time, int_to_hex, hex_to_int

from certification.config import HASH_FUNC


class CRL:
    """
    Represents a CRL - Certificate Revocation List, that every Certificate Authority entity has
    """
    def __init__(self, ca_name, ca_cert, ca_key):
        self._version = 0
        self._ca_name, self._ca_cert, self._ca_key = ca_name, ca_cert, ca_key
        self._crl = crypto.CRL()
        self.revoke()

    def revoke(self, revoked_id=0):
        """
        Revokes a Certificate entity. Note that a Certificate entity can be revoked only it is
        issued by the Certificate Authority entity that issued it!
        :param revoked_id: the ID of the revoked Certificate entity
        :return:
        """
        current_time = get_current_time()

        if revoked_id:
            revoked = crypto.Revoked()
            reason = revoked.all_reasons()[6]

            revoked.set_reason(reason)
            revoked_id_hex = int_to_hex(revoked_id)
            revoked.set_serial(revoked_id_hex.encode())
            revoked.set_rev_date(current_time)
            self._crl.add_revoked(revoked)

        self._crl.set_version(self._version)
        self._version += 1
        self._crl.set_lastUpdate(current_time)

        self._crl.sign(self._ca_cert, self._ca_key, digest=HASH_FUNC.encode())
        self._crl = self._crl.export(self._ca_cert, self._ca_key, digest=HASH_FUNC.encode())
        self._crl = crypto.load_crl(FILETYPE_PEM, self._crl)

        self._save_crl()

    def validate_certificate(self, successor_id, successor_cert, ca_entities_certs):
        """
        Validates a chain of Certificate entities. Note that we begin by checking the validity
        of a "successor" Certificate entity certificate, and then the validity of its
        predecessors (other Certificate Authority entities), in a chain.
        :param successor_id: a suspected Certificate entity
        :param successor_cert: the suspected Certificate entity's certificate
        :param ca_entities_certs: the chain of the Certificate's entity predecessors
        :return:
        """
        self._validate_with_chain(successor_cert, ca_entities_certs)
        self._check_crl_revoked(successor_id)

    def _check_crl_revoked(self, successor_id):
        """
        Checks if the Certificate entity is revoked in the CRL
        :param successor_id: a suspected Certificate entity
        :return:
        """
        revoked_lst = self._crl.get_revoked()
        if not revoked_lst:
            return
        for revoked in self._crl.get_revoked():
            revoked_id = hex_to_int(revoked.get_serial().decode())
            if successor_id == revoked_id:
                raise Error

    def _validate_with_chain(self, successor_cert, ca_entities_certs):
        """
        Validates that the suspected Certificate entity's certificate is signed by authorised
        Certification Authority, that is, is a successor of Certificate Authority. For that
        process, the OpenSSL module requires all the predecessors certificates in a chain.
        :param successor_cert: the terminal Certificate entity which its predecessors chain we
        validate
        :param ca_entities_certs: the Certificate Authority entities which constitute the
        successor and suspected Certificate entity's predecessors
        :return:
        """
        store = X509Store()

        for ca_entity_cert in ca_entities_certs:
            store.add_cert(ca_entity_cert)

        store.set_flags(X509StoreFlags.CRL_CHECK)
        store.add_crl(self._crl)

        ctx = X509StoreContext(store, successor_cert)
        res = ctx.verify_certificate()

        if res is not None:
            raise X509StoreContextError

    def _save_crl(self):
        """
        Saves the CRL
        :return:
        """
        buff = BytesIO()
        buff.write(crypto.dump_crl(FILETYPE_PEM, self._crl))
        with open(key_for_entity_crl(self._ca_name), 'wb') as f:
            f.write(buff.getvalue())
