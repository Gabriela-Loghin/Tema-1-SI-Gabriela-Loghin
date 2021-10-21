from Crypto.Cipher import AES
import socket


# Function used to convert a hexadecimal digit to its' integer corresponding value
def hex_digit_to_int(char: str) -> int:

    # if char is between 0 and 9
    if ord('0') <= ord(char[0]) <= ord('9'):
        return ord(char[0]) - ord('0')

    # if char is between 'a' and 'f'
    if ord('a') <= ord(char[0]) <= ord('f'):
        return ord(char[0]) - ord('a') + 10

    # if char is between 'A' and 'F'
    if ord('A') <= ord(char[0]) <= ord('F'):
        return ord(char[0]) - ord('A') + 10

    raise ValueError(f'Given Digit {char} is not hex')


# Convert group of two hexadecimal chars into a single byte
def hex_2_to_byte(char_set: str) -> bytes:
    return (hex_digit_to_int(char_set[0]) * 16 + hex_digit_to_int(char_set[1])).to_bytes(byteorder='big', length=1)


# Convert hex string into bytes array
def hex_to_bytes(hex_string: str) -> bytes:

    bytes_length = len(hex_string) // 2

    bytes_string = b''

    # Parse hex string in groups of 2i, 2i + 1 ( two chars at a time )
    for i in range(0, bytes_length):

        bytes_string += hex_2_to_byte(hex_string[i * 2:i * 2 + 2])

    return bytes_string


# Perform a single block AES encryption, over given input and with given key
def encrypt_single_block(plain_text: bytes, key: bytes) -> bytes:
    return AES.new(
        key=key,
        mode=AES.MODE_ECB
    ).encrypt(plain_text)


# Perform a single block AES decryption, over given cipher text and with given key
def decrypt_single_block(cipher_text: bytes, key: bytes) -> bytes:
    return AES.new(
        key=key,
        mode=AES.MODE_ECB
    ).decrypt(cipher_text)


# Split a bytes array of indeterminate length into a list of byte arrays, each of length maximum 16
def split(text) :

    blocks=[]

    for i in range(0, len(text), 16):

        blocks.append(text[i:i+16])

    return blocks


# Split a bytes array of indeterminate length into a list of byte arrays, each of length precisely 16
# Last block is padded if needed
def split_and_pad(text: bytes) :

    blocks = split(text=text)

    while len(blocks[-1]) < 16:

        blocks[-1] += b'\000'

    return blocks


# Merge a list of Byte Array blocks of length of exactly 16 bytes each to a single Bytes Array
def merge(blocks) -> bytes:

    text = b''

    for block in blocks:

        text += block

    return text


# Merge a list of Byte Array blocks of length of exactly 16 bytes each to a single Bytes Array,
# while unpadding the last block, if it was padded previously
def unpad_and_merge(blocks) -> bytes:

    while blocks[-1].endswith(b'\000'):

        # Unpad, removing blank characters
         blocks[-1] = blocks[-1][:blocks[-1].rfind(b'\000')]
    return merge(blocks)


# Encryption of plain text into cipher text with ECB
def encrypt_ECB(plain_text: str, key: bytes) -> bytes:

    cipher_text = b''

    for block in split_and_pad(plain_text.encode()):

        # Encrypt each respective Block and add it to the final Cipher Text
        cipher_text += encrypt_single_block(plain_text=block, key=key)

    return cipher_text


# Decryption of cipher text into plain text with ECB
def decrypt_ECB(cipher_text: bytes, key: bytes) -> str:

    blocks = split(cipher_text)

    for i in range(len(blocks)):

        blocks[i] = decrypt_single_block(cipher_text=blocks[i], key=key)

    return unpad_and_merge(blocks=blocks).decode()


# Operation applies XOR over two Byte Arrays, XOR-ing each byte from a with respective byte from b
def xor(a: bytes, b: bytes) -> bytes:

    res = b''

    for i in range(min(len(a), len(b))):
        res += (a[i] ^ b[i]).to_bytes(byteorder='big', length=1)

    return res


# Encryption of plain text into cipher text with CBC
def encrypt_CBC(plain_text: str, key: bytes, iv: bytes) -> bytes:

    cipher_text = b''

    # For each block in split and padded original plain text
    for block in split_and_pad(plain_text.encode()):

        block = xor(a=block, b=iv)

        # obtain cipher text from encryption and save it into iv for next block
        iv = encrypt_single_block(plain_text=block, key=key)

        cipher_text += iv

    return cipher_text


# Decryption of plain text into cipher text with ECB
def decrypt_CBC(cipher_text: bytes, key: bytes, iv: bytes) -> str:

    blocks = split(cipher_text)

    # Parse cipher text blocks
    for i in range(len(blocks)):

        next_iv = blocks[i]

        blocks[i] = decrypt_single_block(cipher_text=blocks[i], key=key)

        blocks[i] = xor(a=blocks[i], b=iv)

        iv = next_iv

    return unpad_and_merge(blocks).decode()


# Function binds a socket and returns the first connection
def await_connection_on(port: int) -> socket.socket:

    # Create a Listening Socket as IPV4 TCP/IP
    listening_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0)

    # Set Setting of Reuse Address to prevent future bind errors
    listening_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    listening_socket.bind(("127.0.0.1", port))

    listening_socket.listen()

    # Receive and Return first connection
    return listening_socket.accept()[0]


def connect_on(port: int) -> socket.socket:

    connecting_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0)

    connecting_socket.connect(('127.0.0.1', port))

    return connecting_socket


# Meta Key K', used to encrypt and decrypt generated key
meta_key: bytes = hex_to_bytes('00112233445566778899aabbccddeeff')

# Globally used IV, used by all nodes
global_iv: bytes = hex_to_bytes('ffeeddccbbaa99887766554433221100')

# Connection port for A to B communication
port_A_to_B = 36000

# Connection port for KM communication
port_KM = 40000

# Response OK Value
response_ok = 'OK'

# Key Request Value
key_request_message = 'Give Encryption Key'

# Start Communication Value
start_communication = 'Start Communication'


# Encryption Modes
class EncryptionMode:
    # ECB is 0
    ECB = 0
    # CBC is 1
    CBC = 1
