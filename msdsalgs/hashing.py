from hashlib import new as hashlib_new
from Crypto.Cipher import DES

from msdsalgs.crypto import transform_des_key

LM_MAGIC_STR = b'KGS!@#$%'


def compute_lm_hash(input_bytes: bytes) -> bytes:
    if len(input_bytes) > 14:
        # TODO: Use proper exception.
        raise ValueError

    input_bytes: bytes = input_bytes.ljust(14, b'\x00')

    return b''.join([
        DES.new(key=transform_des_key(input_bytes[:7]), mode=DES.MODE_ECB).encrypt(plaintext=LM_MAGIC_STR),
        DES.new(key=transform_des_key(input_bytes[7:]), mode=DES.MODE_ECB).encrypt(plaintext=LM_MAGIC_STR)
    ])


def compute_nt_hash(input_bytes: bytes) -> bytes:
    """
    Compute the NT hash of a byte stream.

    This function is also known as NTOWFv1, but has other parameters (Microsoft uses "Passwd, User, UserDom", which is
    completely redundant.

    :param input_bytes: Bytes whose corresponding NT hash to compute.
    :return: The NT hash corresponding to the input bytes.
    """
    return hashlib_new(name='md4', data=input_bytes).digest()
