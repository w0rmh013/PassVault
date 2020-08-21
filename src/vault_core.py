from Crypto.Cipher import AES
from Crypto.Hash import SHA512

import os

import pvlt


class VaultCore(object):
    SHA512_SIZE = 64

    PBKDF2_ITER_COUNT = 2000
    SALT_SIZE = 8  # 64-bit salt size
    KEY_SIZE = 32  # AES-256 key size
    IV_SIZE = AES.block_size

    PVLTFILE_ENVVAR = 'PVLTFILE'

    PVLTFILE_MAGIC = b'PVLT'
    PVLTFILE_MAGIC_SIZE = len(PVLTFILE_MAGIC)

    PVLTFILE_HEADER_SIZE = PVLTFILE_MAGIC_SIZE + SALT_SIZE + IV_SIZE

    def __init__(self, master_password, pvlt_file_name=None):
        """Create VaultCore instance
        
        Args:
            master_password (str): Master password string for vault
            vault_file_name (None, optional): Path to PVLT file (Default: The environment variable 'PVLTFILE')
        
        Raises:
            pvlt.NoVaultFileProvided: Path to PVLT was not provided and does not exist in an environment variable
        """
        # In case a default or custom vault file does not exist
        if not pvlt_file_name and not (pvlt_file_name := os.environ.get(self.PVLTFILE_ENVVAR)):
            raise pvlt.NoVaultFileProvided()
        
        self._file_name = pvlt_file_name

        self._master_password = master_password

        self._data = None

    def _is_pvlt_file(self):
        """Check if instance's file is a PVLT file
        
        Returns:
            bool: True if file is a PVLT file, False else
        """
        if not pvlt.file_exists(self._file_name):
            return False

        with open(self._file_name, 'rb') as pvltfile:
            return pvltfile.read(self.PVLTFILE_MAGIC_SIZE) == self.PVLTFILE_MAGIC

    def _gen_key(self, salt):
        return pvlt.generate_key_from_master_password(self._master_password, salt, self.KEY_SIZE, self.PBKDF2_ITER_COUNT)

    def _encrypt_vault(self, key, iv):
        """Encrypt the vault's data

        Args:
            key (bytes): AES-256 encryption key
            iv (bytes): IV for CBC mode
        
        Returns:
            bytes, bytes. bytes: Encrypted vault data, encrypted vault hash, vault hash
        """

        cipher = AES.new(key, mode=AES.MODE_CBC, IV=iv)

        padded_data = pvlt.pad(self._data, AES.block_size)
        enc_data = cipher.encrypt(padded_data)

        # Calculate hash of encrypted vault data
        vault_hash = pvlt.calc_sha512_hash(enc_data)

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
            bytes: Decrypted vault hash
        """
        cipher = AES.new(key, mode=AES.MODE_CBC, IV=iv)
        
        try:
            data = cipher.decrypt(enc_data)
        except ValueError:
            raise pvlt.CorruptedVaultException()

        dec_vault_hash = data[-self.SHA512_SIZE:]
        self._data = pvlt.unpad(data[:-self.SHA512_SIZE])

        return dec_vault_hash

    def write_to_pvlt_file(self):
        """Write data to PVLT file
        
        Raises:
            pvlt.VaultDataNotInitialized: Vault's is set to None
        """
        if self._data is None:
            raise pvlt.VaultDataNotInitialized()

        salt = pvlt.get_random_bytes(self.SALT_SIZE)
        key = self._gen_key(salt)
        iv = pvlt.get_random_bytes(self.IV_SIZE)

        # Encrypt vault's data
        enc_data, enc_vault_hash, vault_hash = self._encrypt_vault(key, iv)

        with open(self._file_name, 'wb') as pvltfile:
            pvltfile.write(self.PVLTFILE_MAGIC + salt + iv + enc_data + enc_vault_hash + vault_hash)

    def read_from_pvlt_file(self):
        """Read data from PVLT file
        
        Raises:
            pvlt.VaultMasterPasswordIncorrect: Description
        """
        with open(self._file_name, 'rb') as pvltfile:
            # PVLT magic
            pvltfile.read(self.PVLTFILE_MAGIC_SIZE)
            
            salt = pvltfile.read(self.SALT_SIZE)
            iv = pvltfile.read(self.IV_SIZE)

            enc_data = pvltfile.read()

        # Cut vault's integrity hash from encrypted data
        vault_hash = enc_data[-self.SHA512_SIZE:]
        enc_data = enc_data[:-self.SHA512_SIZE]

        key = self._gen_key(salt)

        dec_vault_hash = self._decrypt_vault(key, iv, enc_data)

        if dec_vault_hash != vault_hash:
            self._data = None
            raise pvlt.VaultMasterPasswordIncorrect()
