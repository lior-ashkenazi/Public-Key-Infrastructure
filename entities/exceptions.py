class CertificateAuthorityEntityNotExists(Exception):
    def __init__(self, message, cause=None):
        super(CertificateAuthorityEntityNotExists, self).__init__(message)
        self._cause = cause


class CertificateEntityNotExists(Exception):
    def __init__(self, message, cause=None):
        super(CertificateEntityNotExists, self).__init__(message)
        self._cause = cause


class NonExistentCertificationRelation(Exception):
    def __init__(self, message, cause=None):
        super(NonExistentCertificationRelation, self).__init__(message)
        self._cause = cause
