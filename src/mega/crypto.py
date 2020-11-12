from Crypto.Cipher import AES
import json
import base64
import struct
import binascii
import random
import sys

# Python3 compatibility
if sys.version_info < (3, ):

    def makebyte(x):
        return x

    def makestring(x):
        return x
else:
    import codecs

    def makebyte(x):
        return codecs.latin_1_encode(x)[0]

    def makestring(x):
        return codecs.latin_1_decode(x)[0]

def aes_cbc_encrypt(data, key):
    aes_cipher = AES.new(key, AES.MODE_CBC, makebyte('\0' * 16))
    return aes_cipher.encrypt(data)

def aes_cbc_decrypt(data, key):
    aes_cipher = AES.new(key, AES.MODE_CBC, makebyte('\0' * 16))
    return aes_cipher.decrypt(data)

def aes_cbc_encrypt_a32(data, key):
    return str_to_a32(aes_cbc_encrypt(a32_to_str(data), a32_to_str(key)))

def aes_cbc_decrypt_a32(data, key):
    return str_to_a32(aes_cbc_decrypt(a32_to_str(data), a32_to_str(key)))

def stringhash(str, aeskey):
    '''
    As defined by MEGA's webclient crypto.js. Search for "function stringhash".
    '''
    s32 = str_to_a32(str)
    h32 = [0, 0, 0, 0]
    for (index, word) in enumerate(s32):
        h32[index % 4] ^= word
    for r in range(0x4000):
        h32 = aes_cbc_encrypt_a32(h32, aeskey)
    return a32_to_base64((h32[0], h32[2]))

def prepare_key(arr):
    pkey = [0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56]
    key = [0, 0, 0, 0]
    for r in range(0x10000):
        for j in range(0, len(arr), 4):
            for i in range(4):
                if i + j < len(arr):
                    key[i] = arr[i + j]
                else:
                    key[i] = 0
            pkey = aes_cbc_encrypt_a32(pkey, key)
    return pkey

def encrypt_key(a, key):
    encrypted = tuple(
        piece
        for i in range(0, len(a), 4)
        for piece in aes_cbc_encrypt_a32(a[i:i + 4], key)
    )
    return encrypted

def decrypt_key(a, key):
    decrypted = tuple(
        piece
        for i in range(0, len(a), 4)
        for piece in aes_cbc_decrypt_a32(a[i:i + 4], key)
    )
    return decrypted

def encrypt_attr(attr, key):
    attr = makebyte('MEGA' + json.dumps(attr))
    if len(attr) % 16:
        attr += b'\0' * (16 - len(attr) % 16)
    return aes_cbc_encrypt(attr, a32_to_str(key))

def decrypt_attr(attr, key):
    attr = aes_cbc_decrypt(attr, a32_to_str(key))
    attr = makestring(attr)
    attr = attr.rstrip('\0')
    if '"}\0' in attr:
        attr = attr.split('"}\0')[0] + '"}'
    return json.loads(attr[4:]) if attr[:6] == 'MEGA{"' else False

def a32_to_str(a):
    return struct.pack('>%dI' % len(a), *a)

def str_to_a32(b):
    if isinstance(b, str):
        b = makebyte(b)
    if len(b) % 4:
        # pad to multiple of 4
        b += b'\0' * (4 - len(b) % 4)
    return struct.unpack('>%dI' % (len(b) / 4), b)

def mpi_to_int(s):
    '''
    A Multi-precision integer is encoded as a series of bytes in big-endian
    order. The first two bytes are a header which tell the number of bits in
    the integer. The rest of the bytes are the integer.
    '''
    return int(binascii.hexlify(s[2:]), 16)

def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modular_inverse(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def interleave_xor_8(b):
    return (b[0] ^ b[4], b[1] ^ b[5], b[2] ^ b[6], b[3] ^ b[7])

def base64_url_decode(data):
    data += '=='[(2 - len(data) * 3) % 4:]
    for search, replace in (('-', '+'), ('_', '/'), (',', '')):
        data = data.replace(search, replace)
    return base64.b64decode(data)

def base64_to_a32(s):
    return str_to_a32(base64_url_decode(s))

def base64_url_encode(data):
    data = base64.b64encode(data)
    data = makestring(data)
    for search, replace in (('+', '-'), ('/', '_'), ('=', '')):
        data = data.replace(search, replace)
    return data

def a32_to_base64(a):
    return base64_url_encode(a32_to_str(a))

def get_chunks(size):
    '''
    Given the size of a file in bytes, return tuples (chunk_start, chunk_size)
    for the purposes of downloading or uploading a file in chunks.
    '''
    chunk_start = 0
    chunk_size = 0x20000
    while chunk_start + chunk_size < size:
        yield (chunk_start, chunk_size)
        chunk_start += chunk_size
        # why?
        if chunk_size < 0x100000:
            chunk_size += 0x20000
    yield (chunk_start, size - chunk_start)

def make_id(length):
    possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    text = ''.join(random.choice(possible) for i in range(length))
    return text
