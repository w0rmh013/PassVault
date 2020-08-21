class NoVaultFileProvided(Exception):
    pass


class InvalidVaultFormat(Exception):
    pass


class VaultFileDoesNotExist(Exception):
    pass


class VaultFileExists(Exception):
    pass


class VaultDataNotInitialized(Exception):
    pass


class VaultMasterPasswordIncorrect(Exception):
    pass
