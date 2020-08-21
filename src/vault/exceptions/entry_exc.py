class EntryException(Exception):
	pass


class EntryAlreadyExists(EntryException):
	pass


class EntryDoesNotExist(EntryException):
	pass


class KeyCollisionWithBuiltin(EntryException):
	pass


class NoPasswordForEntry(EntryException):
	pass