from entities.entity import Entity
from entities.ca_entity import CertificateAuthorityEntity


class EntitiesFactory:
    """
    A factory for Certificate entities
    """
    available_counter: int = 1

    @staticmethod
    def _generate_entity_id():
        """
        Returns a new ID for a Certificate entity
        :return: an ID for a Certificate entity
        """
        entity_id = EntitiesFactory.available_counter
        EntitiesFactory.available_counter += 1
        return entity_id

    @staticmethod
    def generate_root_certificate_authority():
        """
        Generates the Root Certificate Authority entity
        :return: the generated Root Certificate Authority entity's ID (always 0) and the Root
        Certificate Authority entity's object
        """
        entity_id = EntitiesFactory._generate_entity_id()
        entity = CertificateAuthorityEntity(entity_id)
        return entity_id, entity

    @staticmethod
    def generate_certificate_authority(ca_entity):
        """
        Generate a Certificate Authority entity
        :param ca_entity: the issuing Certificate Authority
        :return: the generated Certificate Authority entity's ID and the generated Certificate
        Authority entity's object
        """
        entity_id = EntitiesFactory._generate_entity_id()
        entity = CertificateAuthorityEntity(entity_id, ca_entity)
        return entity_id, entity

    @staticmethod
    def generate_certificate(ca_entity):
        """
        Generates a Certificate entity
        :param ca_entity: the issuing Certificate Authority
        :return: the generated Certificate  entity's ID and the generated Certificate entity's
        object
        """
        entity_id = EntitiesFactory._generate_entity_id()
        entity = Entity(entity_id, ca_entity, is_ca=False)
        return entity_id, entity
