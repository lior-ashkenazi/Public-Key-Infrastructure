from entities.entity import Entity

from certification.crl import CRL


class CertificateAuthorityEntity(Entity):
    """
    Represents a Certificate Authority entity
    """
    def __init__(self, entity_id, ca_entity=None):
        super(CertificateAuthorityEntity, self).__init__(entity_id, ca_entity)
        self._crl = CRL(self._name, self._cert, self._key)
        self._successors_id = []

    def get_successors(self):
        """
        Returns the list of the Certificate Authority entity successors
        :return:
        """
        return self._successors_id

    def add_successor(self, successor_id):
        """
        Adds a successor to the list of successors
        :param successor_id:
        :return:
        """
        self._successors_id.append(successor_id)

    def revoke_successor(self, revoked_successor_id):
        """
        Revokes an issued Certificate entity
        :param revoked_successor_id: the ID of the going-to-be revoked Certificate entity
        :return:
        """
        self._crl.revoke(revoked_successor_id)

    def validate_successor(self, successor_id, successor_cert, ca_entities_certs):
        """
        Validates that
        :param successor_id:
        :param successor_cert:
        :param ca_entities_certs:
        :return:
        """
        self._crl.validate_certificate(successor_id, successor_cert, ca_entities_certs)
