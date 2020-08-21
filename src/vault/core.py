from Crypto.Cipher import AES
from Crypto.Hash import SHA512

import os

from .exceptions import *
from .utils import *


class VaultCore(object):
    SHA512_SIZE = 64

    PBKDF2_ITER_COUNT = 2000
    SALT_SIZE = 8  # 64-bit salt size
    KEY_SIZE = 32  # AES-256 key size
    IV_SIZE = AES.block_size

    VAULT_ENVVAR = 'vaultfile'

    VAULT_MAGIC = b'PVLT'
    VAULT_MAGIC_SIZE = len(VAULT_MAGIC)

    def __init__(self, master_password, pvlt_file_name=None):
        """Create VaultCore instance
        
        Args:
            master_password (str): Master password string for vault
            vault_file_name (None, optional): Path to vault file (Default: The environment variable 'vaultfile')
        
        Raises:
            NoVaultFileProvided: Path to vault was not provided and does not exist in an environment variable
        """
        # In case a default or custom vault file does not exist
        if not pvlt_file_name and not (pvlt_file_name := os.environ.get(self.VAULT_ENVVAR)):
            raise NoVaultFileProvided()
        
        self._file_name = pvlt_file_name

        self._master_password = master_password

    def _is_vault_file(self):
        """Check if instance's file is a vault file
        
        Returns:
            bool: True if file is a vault file, False else
        """
        if not file_exists(self._file_name):
            return False

        with open(self._file_name, 'rb') as vaultfile:
            return vaultfile.read(self.VAULT_MAGIC_SIZE) == self.VAULT_MAGIC

    def _check_vault_file(self):
        """Check existence of vault file and its magic
        
        Raises:
            InvalidVaultFormat: Vault file magic is wrong
            VaultFileDoesNotExist: The vault file does not exist
        """
        if not file_exists(self._file_name):
            raise VaultFileDoesNotExist()

        if not self._is_vault_file():
            raise InvalidVaultFormat()

    def _gen_key(self, salt):
        return generate_key_from_master_password(self._master_password, salt, self.KEY_SIZE, self.PBKDF2_ITER_COUNT)

    def _encrypt_vault(self, key, iv, data):
        """Encrypt the vault's data

        Args:
            key (bytes): AES-256 encryption key
            iv (bytes): IV for CBC mode
            data (bytes): Data to encrypt
        
        Returns:
            bytes, bytes. bytes: Encrypted vault data, encrypted vault hash, vault hash
        """

        cipher = AES.new(key, mode=AES.MODE_CBC, IV=iv)

        padded_data = pad(data, AES.block_size)
        enc_data = cipher.encrypt(padded_data)

        # Calculate hash of encrypted vault data
        vault_hash = calc_sha512_hash(enc_data)

        # Encrypt hash of encrypted vault data
        enc_vault_hash = cipher.encrypt(vault_hash)

        return enc_data, enc_vault_hash, vault_hash

    def _decrypt_vault(self, key, iv, enc_data):
        """Decrypt the vault's data and store it in the instance

        Args:
            key (bytes): AES-256 encryption key
            iv (bytes): IV for CBC mode
            enc_data (bytes): Encrypted vault data

        Returns:
            bytes, bytes: Decrypted vault data, decrypted vault hash

        Raises:
            CorruptedVaultException: Vault data is corrupted
        """
        cipher = AES.new(key, mode=AES.MODE_CBC, IV=iv)
        
        try:
            data = cipher.decrypt(enc_data)
        except ValueError:
            raise CorruptedVaultException()

        dec_vault_hash = data[-self.SHA512_SIZE:]

        return unpad(data[:-self.SHA512_SIZE]), dec_vault_hash

    def _write_to_vault_file(self, data):
        """Write data to vault file

        Args:
            data (bytes): Vault data to write to file
        """
        salt = get_random_bytes(self.SALT_SIZE)
        key = self._gen_key(salt)
        iv = get_random_bytes(self.IV_SIZE)

        # Encrypt vault's data
        enc_data, enc_vault_hash, vault_hash = self._encrypt_vault(key, iv, data)

        with open(self._file_name, 'wb') as vaultfile:
            vaultfile.write(self.VAULT_MAGIC + salt + iv + enc_data + enc_vault_hash + vault_hash)

    def _read_from_vault_file(self):
        """Read data from vault file
        
        Returns:
            bytes: Decrypted vault's data

        Raises:
            VaultMasterPasswordIncorrect: Vault's master-password is incorrect
        """
        with open(self._file_name, 'rb') as vaultfile:
            # PVLT magic
            vaultfile.read(self.VAULT_MAGIC_SIZE)
            
            salt = vaultfile.read(self.SALT_SIZE)
            iv = vaultfile.read(self.IV_SIZE)

            enc_data = vaultfile.read()

        # Cut vault's integrity hash from encrypted data
        vault_hash = enc_data[-self.SHA512_SIZE:]
        enc_data = enc_data[:-self.SHA512_SIZE]

        key = self._gen_key(salt)

        data, dec_vault_hash = self._decrypt_vault(key, iv, enc_data)

        if dec_vault_hash != vault_hash:
            raise VaultMasterPasswordIncorrect()

        return data

    def new(self):
        """Create new empty vault file
        
        Raises:
            VaultFileExists: The file already exists
        """
        if file_exists(self._file_name):
            raise VaultFileExists()

        self._write_to_vault_file(b'')

    def read(self):
        """Read data from existing vault file"""
        self._check_vault_file()

        data = self._read_from_vault_file()

        # Each time we read from the vault, the salt and IV changes
        self._write_to_vault_file(data)

        return data

    def write(self, data):
        """Write data to existing vault file
        
        Args:
            data (bytes): Vault data
        """
        self._check_vault_file()

        self._write_to_vault_file(data)
