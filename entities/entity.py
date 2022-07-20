from certification.certificate_generator import CertificateGenerator

from ssl_networking.ssl_client import SSLClient
from ssl_networking.ssl_server import SSLServer

import threading


class Entity:
    """
    Represents a Certificate entity in the PKI ecosystem
    """
    def __init__(self, entity_id,
                 predecessor_entity=None,
                 is_ca=True):
        self._id = entity_id
        self._name = "entity" + str(entity_id)
        self._predecessor_id = 0

        if not predecessor_entity:
            self._cert, self._key, self.cert_file = CertificateGenerator.generate_certificate(
                self._name)

        else:
            self._predecessor_id = predecessor_entity.get_id()
            self._cert,self._key, self.cert_file = CertificateGenerator.generate_certificate(
                predecessor_entity,
                predecessor_entity.get_certificate(),
                predecessor_entity.get_key(),
                self._name,
                is_ca)
            predecessor_entity.add_successor(self._id)

        self._client = SSLClient(str(self), self.cert_file)
        self._server = SSLServer(str(self), self.cert_file)
        self._conn_details = self._server.get_connection_details()
        self._thread = threading.Thread(target=self._server.connect)
        self.run()

    def run(self):
        """
        Runs the Certificate entity's thread. Used for communication with other Certificate
        entities in the PKI ecosystem
        :return:
        """
        self._thread.start()

    def shut(self):
        """
        Shut downs the Certificate entity's thread.
        :return:
        """
        self._thread.join()

    def __repr__(self):
        return self._name.capitalize()

    def validate_other_entity(self, va, other_entity, is_sending=True):
        """
        Validates that a Certificate entity is trusted for safe communication
        :param va: the Validation Authority
        :param other_entity: the suspected Certificate entity
        :param is_sending: is the Certificate entity is sending a message or receiving it
        :return: True/False regarding to if the suspected Certificate entity can be trusted for
        safe communication
        """
        if is_sending:
            print( f"\t{self}: Validating {other_entity}. Hopefully everything is fine.")
        else:
            print(f"\t{self}: Whoa. {other_entity} wants to send me a message. "
                f"Need to make sure that I can trust it. It can be dangerous these days.")

        if va.validate(other_entity):
            print(f"\t{self}: Great! I can trust {other_entity}, its certificate is valid!")
            return True
        else:
            print(f"\t{self}: Oh no! {other_entity}'s certificate is not valid!"
                  f" I can't trust it!")
            return False

    def send(self, msg, server_conn_details):
        """
        Sends a message to a Certificate entity
        :param msg: a message; a string
        :param server_conn_details: details regarding the other Certificate entity's server;
        required for sending a message
        :return:
        """
        self._client.connect(*server_conn_details)
        self._client.send(msg)
        self._client.close()

    def get_id(self):
        """
        :return: the Certificate entity's ID
        """
        return self._id

    def get_predecessor_id(self):
        """
        :return: the issuing Certificate Authority entity's ID
        """
        return self._predecessor_id

    def get_certificate(self):
        """
        :return: the Certificate entity's certificate
        """
        return self._cert

    def get_key(self):
        """
        :return: the Certificate entity certificate's key
        """
        return self._key

    def get_connection_details(self):
        """
        :return: the Certificate entity's server details; necessary for communication with other
        Certificate entities in the PKI ecosystem
        """
        return self._conn_details


