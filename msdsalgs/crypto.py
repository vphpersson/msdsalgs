from struct import pack as struct_pack
from Crypto.Cipher import AES, DES


def has_odd_parity(n: int) -> bool:
    has_add_parity = False
    while n != 0:
        has_add_parity = not has_add_parity
        n &= n - 1
    return has_add_parity


def transform_des_key(input_key: bytes) -> bytes:
    """
    Transform a 7-byte key to a 8-byte key.

    The method of deriving the key is described in section 2.2.11.1.2 of the MS-SAMR documentation: _Encrypting a
    64-Bit Block with a 7-Byte Key_.

    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/ebdb15df-8d0d-4347-9d62-082e6eccac40

    :param input_key: A key to be transformed.
    :return: A proper 8-byte key resulting from the transformation steps.
    """

    out_key = [
        input_key[0] >> 0x01,
        ((input_key[0] & 0x01) << 6) | (input_key[1] >> 2),
        ((input_key[1] & 0x03) << 5 | (input_key[2]) >> 3),
        ((input_key[2] & 0x07) << 4) | (input_key[3] >> 4),
        ((input_key[3] & 0x0F) << 3) | (input_key[4] >> 5),
        ((input_key[4] & 0x1F) << 2) | (input_key[5] >> 6),
        ((input_key[5] & 0x3F) << 1) | (input_key[6] >> 7),
        input_key[6] & 0x7F
    ]

    for i in range(8):
        # Add a 0 bit to the right, to be used as parity bit indicating even parity.
        out_key[i] = (out_key[i] << 1) & 0xfe
        # Calculate the parity of the first seven bits.
        out_key[i] = (out_key[i] | 0x01) if not has_odd_parity(out_key[i]) else out_key[i]

    return bytes(out_key)


def decrypt_aes(key: bytes, value, initialization_vector=b'\x00' * 16) -> bytes:
    """

    :param key:
    :param value:
    :param initialization_vector:
    :return:
    """

    plain_text = b''

    if initialization_vector != b'\x00' * 16:
        aes256 = AES.new(key, AES.MODE_CBC, initialization_vector)

    for i in range(0, len(value), 16):
        if initialization_vector == b'\x00' * 16:
            aes256 = AES.new(key, AES.MODE_CBC, initialization_vector)

        cipher_buffer = value[i:i + 16]

        # Pad buffer to 16 bytes
        if len(cipher_buffer) < 16:
            cipher_buffer += b'\x00' * (16 - len(cipher_buffer))

        plain_text += aes256.decrypt(cipher_buffer)

    return plain_text


class DesEcbLmCipher:
    """
    [MS-SAMR] 2.2.11.1 DES-ECB-LM
    """

    def __init__(self, key_1: bytes, key_2: bytes):
        """
        Make a DES-ECB-LM cipher.

        This type of cipher is used by Microsoft to encrypt and decrypt NT and LM hashes.

        :param key_1: An 8-byte key with which to operate on Block 1 (the first 8 bytes of the data).
        :param key_2: An 8-byte key with which to operate on Block 2 (the last 8 bytes of the data)
        """

        des_key_1, des_key_2 = transform_des_key(key_1), transform_des_key(key_2)

        self._des_cipher_1 = DES.new(des_key_1, DES.MODE_ECB)
        self._des_cipher_2 = DES.new(des_key_2, DES.MODE_ECB)

    def encrypt(self, hash_bytes: bytes) -> bytes:
        if len(hash_bytes) != 16:
            raise ValueError('The provided data is neither an NT nor LM hash.')

        return self._des_cipher_1.encrypt(hash_bytes[:8]) + self._des_cipher_2.encrypt(hash_bytes[8:])

    def decrypt(self, encrypted_hash: bytes) -> bytes:
        if len(encrypted_hash) != 16:
            raise ValueError('The provided data is neither an encrypted NT nor LM hash.')

        return self._des_cipher_1.decrypt(encrypted_hash[:8]) + self._des_cipher_2.decrypt(encrypted_hash[8:])

    @classmethod
    def from_int_key(cls, int_key: int) -> 'DesEcbLmCipher':
        """
        Initiate a DES-ECB-LM cipher from an unsigned integer key.

        The method of deriving key 1 and key 2 is described section 2.2.11.1.3 of the MS-SAMR documentation:
        _Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key_.

        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/b1b0094f-2546-431f-b06d-582158a9f2bb

        :param int_key: An unsigned integer key with which to initiate the cipher.
        :return: A DES-ECB-LM cipher.
        """

        key: bytes = struct_pack('<L', int_key)
        return cls(
            key_1=key[0:1] + key[1:2] + key[2:3] + key[3:4] + key[0:1] + key[1:2] + key[2:3],
            key_2=key[3:4] + key[0:1] + key[1:2] + key[2:3] + key[3:4] + key[0:1] + key[1:2]
        )

    @classmethod
    def from_bytes_key(cls, key: bytes) -> 'DesEcbLmCipher':
        """
        Initiate a DES-ECB-LM cipher from a 16-byte key.

        The method of deriving key 1 and key 2 is described in section 2.2.11.1.4 of the MS-SAMR documentation:
        _Deriving Key1 and Key2 from a 16-Byte Key_.

        https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/ba437786-7de8-47b4-b269-5a595c255327

        :param key: A 16-byte key with which to initiate the cipher.
        :return: A DES-ECB-LM cipher.
        """

        if len(key) != 16:
            raise ValueError('The key must be of length 16.')

        return cls(key_1=key[0:7], key_2=key[7:14])
