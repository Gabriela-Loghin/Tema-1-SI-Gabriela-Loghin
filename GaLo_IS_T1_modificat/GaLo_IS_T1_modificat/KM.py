from utils import *
from Crypto import Random


def main() -> None:
    # NODE KM

    socket_to_A = await_connection_on(port_KM)

    message = socket_to_A.recv(1024).decode()

    if message != key_request_message:

        # Throw Exception due to Bad Message
        raise RuntimeError(f'Invalid Request received from A : {message}')

    # Generate Encryption Key K
    encryption_key: bytes = Random.new().read(16)

    # Encrypt Generated Key K with Meta Key K' and send it to Node A
    socket_to_A.send(encrypt_single_block(plain_text=encryption_key, key=meta_key))

    socket_to_A.close()


if __name__ == '__main__':
    main()
