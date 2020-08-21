from Crypto.Hash import SHA512
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

import os


def file_exists(file_path):
    """Check if a path exists and is a file
    
    Args:
        file_path (str): System path
    
    Returns:
        bool: True if path exists and is a file, False else
    """
    return os.path.exists(file_path) and os.path.isfile(file_path)


def generate_key_from_master_password(master_password, salt, key_size, iter_count):
    """Generate key in given size via PBKDF2 with number of iterations
    from password with salt
    
    Args:
        master_password (str): Master password string
        salt (bytes): Salt to use in PBKDF2
        key_size (int): Size of output key
        iter_count (TYPE): Number of iterations for PBKDF2

    Returns:
        bytes: Key of given size
    """
    return PBKDF2(master_password, salt=salt, dkLen=key_size, count=iter_count)


def calc_sha512_hash(data):
    """Calculate SHA512 hash of data
    
    Args:
        data (bytes): Data to hash
    
    Returns:
        bytes: Digest of SHA512 data hash
    """
    return SHA512.new(data).digest()


def pad(x, bs):
    """PKCS#7 padding
    
    Args:
        x (bytes): Data
        bs (int): Desired block size
    
    Returns:
        bytes: Padded data
    """
    ps = (bs - len(x)) % bs
    
    if ps == 0:
        ps = bs

    return x + (chr(ps) * ps).encode()


def unpad(x):
    return x[:-x[-1]]
