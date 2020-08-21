import os

import pvlt


class Vault(object):
	PVLTFILE_ENVVAR = 'PVLTFILE'
	PVLTFILE_MAGIC = b'PVLT'

	def __init__(self, vault_file_name=None):
		# In case a default or custom vault file does not exist
		if not vault_file_name and not (vault_file_name := os.environ.get(Vault.PVLTFILE_ENVVAR)):
			raise pvlt.NoVaultFileProvided()
		
		self._file_name = vault_file_name

	def _is_pvlt_file(self):
		with open(self._file_name, 'rb') as pvltfile:
			return pvltfile.read(4) == Vault.PVLTFILE_MAGIC:

	def create(self):
		if pvlt.file_exists(self._file_name):
			raise pvlt.VaultFileExists()


def main():
	v = Vault()


if __name__ == '__main__':
	main()
