from certification.certificate_authority import CertificateAuthority

from certification.utils import key_for_entity

class CertificateGenerator:
    """
    Generates certificates (x509) for Certificate entities
    """
    @staticmethod
    def generate_certificate(ca_name, ca_cert=None, ca_key=None, entity_name=None,is_ca=True):
        """
        Generates certificates (x509) for Certificate entities
        :param ca_name: the issuing Certificate Authority entity's name
        :param ca_cert: the issuing Certificate Authority entity's certificate
        :param ca_key: the issuing Certificate Authority entity certificate's key
        :param entity_name: the issued Certificate entity name
        :param is_ca: is the issued Certificate Entity is authorised one, that is, a Certificate
        Authority entity
        :return: a x509 certificate, a key to the certificate and the path to the saved certificate
        """
        # Note that here there are two options:
        # 1. We load an already generated root certificate authority;
        # 2. We generate a new one.
        ca = CertificateAuthority(ca_name=ca_name,ca_cert=ca_cert,ca_key=ca_key)

        if not entity_name:
            # Just *generate* the root certificate
            ca_cert, ca_key = ca.generate_root_ca_certificate()
            return ca_cert, ca_key, key_for_entity(ca_name)

        else:
            if is_ca:
                # Sign a certificate for a given entity which
                # also going to be a Certificate Authority
                ca_cert, ca_key = ca.generate_certificate_authority_entity(entity_name)
                cert, key = ca_cert, ca_key
            else:
                # Sign a certificate for a given entity which
                # also going to be a Certificate Authority
                cert, key = ca.generate_certificate_entity(entity_name)
            return cert, key, key_for_entity(entity_name)
