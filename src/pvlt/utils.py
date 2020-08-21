import os


def file_exists(file_path):
	return os.path.exists(file_path) and os.path.isfile(file_path)
