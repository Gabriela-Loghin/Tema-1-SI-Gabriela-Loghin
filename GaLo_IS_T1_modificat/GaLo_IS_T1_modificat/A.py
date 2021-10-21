from utils import *


def main() -> None:
    # NODE A

    socket_to_KM = connect_on(port_KM)

    socket_to_B = await_connection_on(port_A_to_B)

    # Wrap for any error catch
    try:

        # Chosen Encryption Mode
        encryption_type = -1

        # While input is not valid ( not ECB or CBC )
        while True:

            # Wrap for Error in converting str to int
            try:

                encryption_type = int(input('Acquire Block Encryption Mode : ECB = 0, CBC = 1 : '))

                if encryption_type == EncryptionMode.ECB or encryption_type == EncryptionMode.CBC:
                    break

            # If error, given input is not int convertible
            except ValueError as _:
                pass

        socket_to_KM.send(key_request_message.encode())

        socket_to_B.send(encryption_type.to_bytes(length=4, byteorder='big'))

        encryption_key = decrypt_single_block(cipher_text=socket_to_KM.recv(16), key=meta_key)

        socket_to_B.send(encrypt_single_block(plain_text=encryption_key, key=meta_key))

        print(f'A got encryption key : {encryption_key}')

        message = socket_to_B.recv(1024).decode()

        if message != start_communication:

            raise RuntimeError(f'Invalid Message received from B : {message}')

        # Jump to Transfer Logic, passing socket to B, File Name, Encryption Key and Type
        transfer_file(socket_to_B, 'A.py', encryption_key, encryption_type)

    except Exception as exception:

        print(exception)

    socket_to_B.close()

    socket_to_KM.close()

# File Transfer Function
def transfer_file(s, file_name, key, enc_type) -> None:

    # In case of error, jump to Exception
    try:

        # Open File with given path in Read Mode
        with open(file_name, 'r') as input_file:

            file_data = input_file.read()

            # Encrypt Data in the requested Encryption Mode and Split it into Blocks of 16 bytes
            # If using ECB, use only key and input
            # If using CBC, use key, input and initialization vector
            blocks = split(encrypt_ECB(file_data, key) if enc_type == EncryptionMode.ECB else
                           encrypt_CBC(file_data, key, global_iv))

            s.send(len(blocks).to_bytes(byteorder='big', length=4))

            # For Each Block
            for block in blocks:

                s.send(block)

            input_file.close()

    except IOError as error:

        raise RuntimeError(f'Invalid path for file. Might not exist : {file_name}, {error}')


if __name__ == '__main__':
    main()
