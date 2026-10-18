import random


def crypt(data, byte_map, len_):
    for i in range(len_):
        data[i] = byte_map[data[i]]


class SimpleCryptography:
    """Simple Cryptography

    This crypto algorithm uses a random uint8 map to transfer an uint8 to another uint8.
    So, the decryption process does not depend on previous decrypted data.

    The algorithm is vulnerable, so NO using to encrypt important data.
    """

    def __init__(self, key):
        rg = random.Random()
        rg.seed(key, version=2)

        _byte_map = list(range(1 << 8))
        rg.shuffle(_byte_map)

        # encrypt_byte_map[ori_char] -> encrypted_char
        self._encrypt_byte_map = bytes(bytearray(_byte_map))

        # decrypt_byte_map[encrypted_char] -> ori_char
        self._decrypt_byte_map = bytes(
            bytearray(
                [c for _, c in sorted(zip(_byte_map, range(1 << 8), strict=True))]
            )
        )

        self._key = key

    def encrypt(self, data):
        # 必须是 bytearray：crypt() 原地改写，bytes 不支持下标赋值。
        # 原先写的是 bytes(bytearray(data))，任何调用都直接 TypeError。
        buf = bytearray(data)  # copy
        crypt(buf, self._encrypt_byte_map, len(buf))
        return bytes(buf)

    def decrypt(self, data):
        buf = bytearray(data)  # copy
        crypt(buf, self._decrypt_byte_map, len(buf))
        return bytes(buf)

    def reset(self):
        pass
