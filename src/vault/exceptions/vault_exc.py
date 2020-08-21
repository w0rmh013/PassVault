class VaultException(Exception)


class NoVaultFileProvided(VaultException):
    pass


class InvalidVaultFormat(VaultException):
    pass


class VaultFileDoesNotExist(VaultException):
    pass


class VaultFileExists(VaultException):
    pass


class VaultMasterPasswordIncorrect(VaultException):
    pass


class CorruptedVaultException(VaultException):
    pass
