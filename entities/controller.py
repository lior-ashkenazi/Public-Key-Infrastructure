from entities.entity import Entity
from entities.ca_entity import CertificateAuthorityEntity
from entities.entities_factory import EntitiesFactory
from entities.exceptions import \
    CertificateAuthorityEntityNotExists, \
    CertificateEntityNotExists, \
    NonExistentCertificationRelation
from entities.validation_authority import ValidationAuthority

from typing import Dict

from time import sleep


class Controller:
    """
    Oversees the run and management of the Certificate entities
    """
    _ca_entities: Dict[int, CertificateAuthorityEntity] = {}
    _entities: Dict[int, Entity] = {}

    @staticmethod
    def generate():
        """
        Handles the generation of Certificate entities
        :return:
        """
        print("These are the 'generate' commands:")
        print('\tr - Generate Root Certificate Authority Entity')
        print('\tc - Generate Certificate Authority Entity')
        print('\te - Generate Certificate Entity')
        print("Now then.")
        while True:
            cmd = input("Enter command: ")
            if cmd in {'r', 'c', 'e'}:
                if cmd == 'r':
                    Controller._generate_root_certificate_authority()
                elif cmd == 'c':
                    Controller._generate_certificate_authority()
                elif cmd == 'e':
                    Controller._generate_certificate()
                break
            else:
                print("Unknown command. Please see above the correct commands for this task.")

    @staticmethod
    def _generate_root_certificate_authority():
        """
        Handles the generation of the Root Certificate Authority entity
        :return:
        """
        root_ca_entity_id, root_ca_entity = EntitiesFactory.generate_root_certificate_authority()
        Controller._ca_entities[root_ca_entity_id] = root_ca_entity
        Controller._entities[root_ca_entity_id] = root_ca_entity
        print(f'Say hello! Root Certificate Authority, known as {root_ca_entity} has been created!')

    @staticmethod
    def _generate_certificate_authority():
        """
        Handles the generation of Certificate Authority entities
        :return:
        """
        # Note: every entity can have a child, BUT only root entities don't have a predecessor
        predecessor_ca_id = int(input("Enter the Certificate Authority ID to authorise the "
                                      "certificate of the generated entity: "))
        if predecessor_ca_id in Controller._ca_entities:
            print(f'Good, {Controller._ca_entities[predecessor_ca_id]} has been chosen as the '
                  f'Certificate Authority.')
        else:
            raise CertificateAuthorityEntityNotExists(
                "There is no such Certificate Authority entity!\n"
                "Perhaps try to fresh your memory and see what are "
                "the Certificate Authority entities who exists.")
        predecessor_ca = Controller._ca_entities[predecessor_ca_id]
        ca_entity_id, ca_entity = EntitiesFactory.generate_certificate_authority(predecessor_ca)
        Controller._ca_entities[ca_entity_id] = ca_entity
        Controller._entities[ca_entity_id] = ca_entity
        print(f'Congrats! {ca_entity} has been created!')

    @staticmethod
    def _generate_certificate():
        """
        Handles the generation of Certificate entities, *not* authorised ones.
        :return:
        """
        # Note: every entity can have a child, BUT only root entities don't have a predecessor
        predecessor_ca_id = int(input("Enter the Certificate Authority ID to authorise the "
                                      "certificate of the generated entity: "))
        if predecessor_ca_id in Controller._ca_entities:
            print(f'Good, {Controller._ca_entities[predecessor_ca_id]} has been chosen as the '
                  f'Certificate Authority.')
        else:
            raise CertificateAuthorityEntityNotExists(
                "There is no such Certificate Authority entity!\n"
                "Perhaps try to fresh your memory and see what are "
                "the Certificate Authority entities who exists.")
        predecessor_ca = Controller._ca_entities[predecessor_ca_id]
        entity_id, entity = EntitiesFactory.generate_certificate(predecessor_ca)
        Controller._entities[entity_id] = entity
        print(f'Congrats! {entity} has been created!')

    @staticmethod
    def send_message():
        """
        Sends a message from one Certificate entity to another
        :return:
        """
        sender_entity_id = int(input("Choose an entity for sending a message: "))
        if sender_entity_id not in Controller._entities:
            raise CertificateEntityNotExists("There is no such entity!")
        receiver_entity_id = int(input(("Very Well. Now, choose the entity for receiving the "
                                        "message: ")))
        if receiver_entity_id not in Controller._entities:
            raise CertificateEntityNotExists("There is no such entity!")
        while True:
            msg = input("Good. Now enter a message: ")
            if msg:
                sender_entity = Controller._entities[sender_entity_id]
                receiver_entity = Controller._entities[receiver_entity_id]
                va = ValidationAuthority(Controller._ca_entities)
                if not sender_entity.validate_other_entity(va, receiver_entity):
                    break
                if not receiver_entity.validate_other_entity(va, sender_entity, is_sending=False):
                    break
                sender_entity.send(msg, receiver_entity.get_connection_details())
                sleep(1)
                break
            print("Can you please enter an actual message?")

    @staticmethod
    def show_entities():
        """
        Handles the printing of Certificate entities in the PKI ecosystem
        :return:
        """
        print("These are the 'show' commands:")
        print("\t a - Show all entities")
        print("\t c - Show all Certificate Authority entities")
        print("\t v - Show all Certificate Authority entities verbosely, namely with successors")
        while True:
            cmd = input("Enter 'show' command: ")
            if cmd in {'a', 'c', 'v'}:
                if cmd == 'a':
                    Controller._print_entities()
                elif cmd == 'c':
                    Controller._print_ca_entities()
                elif cmd == 'v':
                    Controller._print_ca_entities_verbose()
                break
            else:
                print("Unknown command. Please see above the correct commands for this task.")

    @staticmethod
    def _print_ca_entities():
        """
        Prints all the Certificate Authority entities in the PKI ecosystem
        :return:
        """
        if not Controller._ca_entities:
            print("There are no Certificate Authority Entities!")
        else:
            print("Certificate Authority Entities:")
            for entity_id in Controller._ca_entities:
                print(Controller._ca_entities[entity_id], end=" ")

    @staticmethod
    def _print_entities():
        """
        Print all the Certificate entities in the PKI ecosystem
        :return:
        """
        if not Controller._entities:
            print("There are no Certificate Entities!")
        else:
            print("Certificate Entities:")
            for entity_id in Controller._entities:
                print(Controller._entities[entity_id], end=" ")

    @staticmethod
    def _print_ca_entities_verbose():
        """
        Prints all the Certificate Authority entities and their issued Certificate entities
        :return:
        """
        if not Controller._ca_entities:
            print("There are no Certificate Authority Entities!")
        else:
            print("Certificate Authority Entities:")
            for entity_id in Controller._ca_entities:
                print(Controller._ca_entities[entity_id], end=" ")
                print()
                successors_id = Controller._ca_entities[entity_id].get_successors()
                if not successors_id:
                    print("No Successors.")
                else:
                    print("Successors:")
                    for successor_id in successors_id:
                        print(Controller._entities[successor_id], end=" ")
                    print()
                print()

    @staticmethod
    def revoke():
        """
        Handles the revocation of a Certificate entity, permitted only to the Certificate
        Authority entity which issued it
        :return:
        """
        print("Oh, that's unfortunate.")
        revocation_authority_id = int(input("Enter Certificate Authority entity who will revoke: "))
        if revocation_authority_id not in Controller._ca_entities:
            raise CertificateEntityNotExists("There is no such entity!")
        print("Ok.")
        revoked_id = int(input("Enter entity who will be revoked: "))
        if revoked_id not in Controller._entities:
            raise CertificateEntityNotExists("There is no such entity!")
        elif revoked_id not in Controller._ca_entities[revocation_authority_id].get_successors():
            raise NonExistentCertificationRelation(
                f"Invalid revocation request, {Controller._ca_entities[revocation_authority_id]} "
                f"did not issue {Controller._entities[revoked_id]}.")
        Controller._ca_entities[revocation_authority_id].revoke_successor(revoked_id)
        print(f"Revocation complete. {Controller._ca_entities[revocation_authority_id]} revoked "
              f"{Controller._entities[revoked_id]} successfully.")

    @staticmethod
    def shut_entities():
        """
        Shuts down all the entities
        :return:
        """
        for _, entity in Controller._entities.items():
            del entity
        for _, entity in Controller._ca_entities.items():
            del entity
