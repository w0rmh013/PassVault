import pvlt
from vault_core import VaultCore


class Vault(VaultCore):
    def __init__(self, master_password, pvlt_file_name=None):
        """Create Vault instance
        
        Args:
            master_password (str): Master password string for vault
            vault_file_name (None, optional): Path to PVLT file (Default: The environment variable 'PVLTFILE')
        """
        super().__init__(master_password, pvlt_file_name)

    def new(self):
        """Create new empty PVLT file
        
        Raises:
            pvlt.VaultFileExists: The file already exists
        """
        if pvlt.file_exists(self._file_name):
            raise pvlt.VaultFileExists()

        self._data = b''
        self.write_to_pvlt_file()

    def open(self):
        """Open existing PVLT file
        
        Raises:
            pvlt.InvalidVaultFormat: PVLT file magic is wrong
            pvlt.VaultFileDoesNotExist: The PVLT file does not exist
        """
        if not pvlt.file_exists(self._file_name):
            raise pvlt.VaultFileDoesNotExist()

        if not self._is_pvlt_file():
            raise pvlt.InvalidVaultFormat()

        self.read_from_pvlt_file()

    def add(self, data):
        self._data = data
        self.write_to_pvlt_file()
