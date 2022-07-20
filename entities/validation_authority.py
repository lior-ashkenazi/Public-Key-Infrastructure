from OpenSSL.crypto import X509StoreContextError, Error


class ValidationAuthority:
    """
    Represents the Validation Authority in the PKI ecosystem. The only entity that is authorised
    to validate the certificates of any Certificate entities, by validating the CRLs.
    """
    def __init__(self, ca_entities):
        self._ca_entities = ca_entities

    def validate(self, suspected_entity):
        """
        Validates a suspected Certificate entity
        :param suspected_entity: a Certificate entity
        :return: True/False regarding if the given Certificate entity is trusted
        """
        try:
            ca_entities = self._get_certificate_authority_entities(suspected_entity)

            for i, ca_entity in enumerate(ca_entities):
                suspected_entity_id = suspected_entity.get_id()
                suspected_entity_cert = suspected_entity.get_certificate()
                ca_entities_certs = [ca.get_certificate() for ca in ca_entities[i:]]
                ca_entity.validate_successor(suspected_entity_id,
                                             suspected_entity_cert,
                                             ca_entities_certs)
                suspected_entity = self._ca_entities[suspected_entity.get_predecessor_id()]
        except (X509StoreContextError, Error):
            return False
        else:
            return True

    def _get_certificate_authority_entities(self, suspected_entity):
        """
        Returns a list of all the predecessors of a suspected Certificate entity. Note that all
        the predecessors are Certificate Authority entities
        :param suspected_entity: a Certificate entity
        :return: a list of all the predecessors of a suspected Certificate entity
        """
        cas = []
        while suspected_entity.get_predecessor_id():
            predecessor_entity_id = suspected_entity.get_predecessor_id()
            predecessor_entity = self._ca_entities[predecessor_entity_id]
            cas.append(predecessor_entity)
            suspected_entity = predecessor_entity
        return cas
