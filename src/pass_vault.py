import json
import time

import vault


class PassVault(vault.VaultCore):
    LAST_MODIFIED = 'last_modified'
    LAST_REVEALED = 'last_revealed'
    BUILTINS = [LAST_MODIFIED, LAST_REVEALED]

    PASSWORD = 'password'
    HIDDEN_PASSWORD = '*'*8

    TIME_FORMAT = '%d-%m-%Y %H:%M:%S'

    def __init__(self, master_password, vault_file_name=None):
        """Create Vault instance
        
        Args:
            master_password (str): Master password string for vault
            vault_file_name (None, optional): Path to vault file (Default: The environment variable 'PVLTFILE')
        """
        super().__init__(master_password, vault_file_name)

        self._data = dict()

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

    def new(self):
        """Create new vault with empty data"""
        super().new(self._encode())

    def load(self):
        """Load vault data from file"""
        data = self.read()
        self._decode(data)

    def save(self):
        """Save vault data to file"""
        data = self._encode()
        self.write(data)
        self._data = None

    def _entry_exists(self, entry_id):
        """Check if entry exists in vault's data
        
        Args:
            entry_id (str): Entry ID
        
        Returns:
            bool: True if entry exists, False else
        """
        return entry_id in self._data

    def _valid_properties(self, properties):
        """Check if properties contain key 'password' and do not contain BUILTIN keys
        
        Args:
            properties (dict): Properties of entry (must have 'password' key and must not contain any BUILTINS)
        
        Raises:
            vault.KeyCollisionWithBuiltin: One of the properties' keys is a BUILTIN
            vault.NoPasswordForEntry: There's no 'password' key in properties
        """
        # Check that user did not use any builtin names as keys
        if any(key in self.BUILTINS for key in properties):
            raise vault.KeyCollisionWithBuiltin()

        # There must be a password key for every entry
        if all(key != self.PASSWORD for key in properties):
            raise vault.NoPasswordForEntry()

    def add_entry(self, entry_id, properties, check_existence=True):
        """Add entry to vault
        
        Args:
            entry_id (str): Entry ID
            properties (dict): Properties of entry (must have 'password' key and must not contain any BUILTINS)
        
        Raises:
            vault.EntryAlreadyExists: Entry with same ID already exists in the vault
        """
        if check_existence and self._entry_exists(entry_id):
            raise vault.EntryAlreadyExists()

        self._valid_properties(properties)

        # Set properties for entry and add builtins
        self._data[entry_id] = properties
        self._data[entry_id][self.LAST_MODIFIED] = time.time()
        self._data[entry_id][self.LAST_REVEALED] = None

    def del_entry(self, entry_id, sure=False):
        """Delete entry from vault
        
        Args:
            entry_id (str): Entry ID
            sure (bool, optional): When set to False, user will be prompted to confirm deletion
        
        Raises:
            vault.EntryDoesNotExist: Entry ID doesn't exist in the vault
        """
        if not self._entry_exists(entry_id):
            raise vault.EntryDoesNotExist()

        if not sure and not vault.yes_no_prompt(f'Are you sure you want to delete entry "{entry_id}"?'):
            return

        self._data[entry_id].pop()

    def edit_entry(self, entry_id, properties, sure=False):
        """Edit entry inside vault's data
        
        Args:
            entry_id (str): Entry ID
            properties (dict): Properties of entry (must have 'password' key and must not contain any BUILTINS)
            sure (bool, optional): When set to False, user will be prompted to confirm deletion
        
        Raises:
            vault.EntryDoesNotExist: Entry ID doesn't exist in the vault
        """
        if not self._entry_exists(entry_id):
            raise vault.EntryDoesNotExist()

        if not sure and not vault.yes_no_prompt(f'Are you sure you want to edit entry "{entry_id}"?'):
            return

        self.add_entry(entry_id, properties, check_existence=False)

    def get_entry(self, entry_id, hide_password=True):
        """Get entry data from vault
        
        Args:
            entry_id (str): Entry ID
        
        Returns:
            dict: Data of entry
        
        Raises:
            vault.EntryDoesNotExist: Entry ID doesn't exist in the vault
        """
        if not self._entry_exists(entry_id):
            raise vault.EntryDoesNotExist()

        copy_data = dict(self._data[entry_id])
        if hide_password:
            copy_data[self.PASSWORD] = self.HIDDEN_PASSWORD
        else:
            # Password is revealed, update field
            self._data[entry_id][self.LAST_REVEALED] = time.time()
            copy_data[self.LAST_REVEALED] = self._data[entry_id][self.LAST_REVEALED]

        # Convert time in seconds to human-readable format
        copy_data[self.LAST_MODIFIED] = vault.seconds_to_human_readable(self.TIME_FORMAT, self._data[entry_id][self.LAST_MODIFIED])
        if self._data[entry_id][self.LAST_REVEALED]:
            copy_data[self.LAST_REVEALED] = vault.seconds_to_human_readable(self.TIME_FORMAT, self._data[entry_id][self.LAST_REVEALED])
        else:
            copy_data[self.LAST_REVEALED] = None

        return copy_data

    def get_password(self, entry_id):
        """Get password from vault entry
        
        Args:
            entry_id (str): Entry ID
        
        Returns:
            str: Password for entry
        
        Raises:
            vault.EntryDoesNotExist: Entry ID doesn't exist in the vault
        """
        if not self._entry_exists(entry_id):
            raise vault.EntryDoesNotExist()

        # Password is revealed, update field
        self._data[entry_id][self.LAST_REVEALED] = time.time()
        return self._data[entry_id]['password']

    def list_entries(self):
        """List all entries in vault by ID 
        
        Returns:
            dict_keys: List of entry IDs
        """
        return self._data.keys()

    def summary(self, only_builtins=True, hide_passwords=True):
        """Get summary of vault's data

        Args:
            only_builtins (bool, optional): If set to True, only builtin keys are returned for each entry
            hide_passwords (bool, optional): If set to True, passwords in data are replaced with filler string
        
        Returns:
            dict: Dictionary with vault data
        """
        copy_data = dict()

        for entry_id in self._data:
            # If only builtins, start with empty dict
            if only_builtins:
                copy_data[entry_id] = dict()
            else:
                copy_data[entry_id] = dict(self._data[entry_id])
                # Replace password with filler string
                if hide_passwords:
                    copy_data[entry_id][self.PASSWORD] = self.HIDDEN_PASSWORD
                else:
                    # Password is revealed, update field
                    self._data[entry_id][self.LAST_REVEALED] = time.time()

            # Convert time in seconds to human-readable format
            copy_data[entry_id][self.LAST_MODIFIED] = vault.seconds_to_human_readable(self.TIME_FORMAT, self._data[entry_id][self.LAST_MODIFIED])
            copy_data[entry_id][self.LAST_REVEALED] = vault.seconds_to_human_readable(self.TIME_FORMAT, self._data[entry_id][self.LAST_REVEALED])
        
        return copy_data
