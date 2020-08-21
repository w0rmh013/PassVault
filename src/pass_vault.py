import json
import time

import vault


class PassVault(vault.VaultCore):
    CREATION_TIME = 'creation_time'
    LAST_COPY_TIME = 'last_copy_time'
    BUILTINS = [CREATION_TIME, LAST_COPY_TIME]

    PASSWORD = 'password'

    def __init__(self, master_password, vault_file_name=None):
        """Create Vault instance
        
        Args:
            master_password (str): Master password string for vault
            vault_file_name (None, optional): Path to vault file (Default: The environment variable 'PVLTFILE')
        """
        super().__init__(master_password, vault_file_name)

        self._data = None

    def _encode(self):
        """Encode vault data to JSON
        
        Returns:
            bytes: JSON Byte-string with vault data
        """
        return json.dumps(self._data).encode()

    def _decode(self, data):
        """Decode decrypted JSON vault data
        
        Args:
            data (bytes): Vault data
        
        Raises:
            vault.CorruptedVaultException: Cannot decode data, vault is corrupted
        """
        try:
            self._data = json.loads(data)
        except ValueError:
            raise vault.CorruptedVaultException()

    def load(self):
        """Load vault data from file"""
        data = self.read()
        self._decode(data)

    def save(self):
        """Save vault data to file"""
        data = self._encode(self._data)
        self.write(data)
        self._data = None

    def add_entry(self, entry_id, properties):
        """Add entry to vault
        
        Args:
            entry_id (str): Entry ID
            properties (dict): Properties of entry (must have 'password' key and must not contain any BUILTINS)
        
        Raises:
            vault.EntryAlreadyExists: Entry with same ID already exists in the vault
            vault.KeyCollisionWithBuiltin: One of the properties' keys is a BUILTIN
            vault.NoPasswordForEntry: There's no 'password' key in properties
        """
        if entry_id in self._data.keys():
            raise vault.EntryAlreadyExists()

        # Check that user did not use any builtin names as keys
        if any(key in self.BUILTINS for key in properties.keys()):
            raise vault.KeyCollisionWithBuiltin()

        # There must be a password key for every entry
        if all(key != self.PASSWORD for key in properties.keys()):
            raise vault.NoPasswordForEntry()

        # Set properties for entry and add builtins
        self._data[entry_id] = properties
        self._data[entry_id][self.CREATION_TIME] = time.time()
        self._data[entry_id][self.LAST_COPY_TIME] = None

    def del_entry(self, entry_id, sure=False):
        """Delete entry from vault
        
        Args:
            entry_id (str): Entry ID
            sure (bool, optional): When set to False, user will be prompted to confirm deletion
        """
        if entry_id not in self._data.keys:
            raise vault.EntryDoesNotExist()

        if not sure and not vault.yes_no_prompt(f'Are you sure you want to delete entry "{entry_id}"?'):
            return

        self._data[entry_id].pop()
