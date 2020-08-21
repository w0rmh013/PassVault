import vault


class PassVault(vault.VaultCore):
    def __init__(self, master_password, pvlt_file_name=None):
        """Create Vault instance
        
        Args:
            master_password (str): Master password string for vault
            vault_file_name (None, optional): Path to vault file (Default: The environment variable 'PVLTFILE')
        """
        super().__init__(master_password, pvlt_file_name)
