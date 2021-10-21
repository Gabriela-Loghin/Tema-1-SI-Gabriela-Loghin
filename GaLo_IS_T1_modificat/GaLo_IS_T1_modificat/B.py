from utils import *


def main() -> None:
    # NODE B

    socket_to_A = connect_on(port_A_to_B)

    # Wrap for any error catch
    try:

        encryption_type = int(int.from_bytes(bytes=socket_to_A.recv(4), byteorder='big'))

        print(f'Encryption Mode chosen : {"ECB" if encryption_type == EncryptionMode.ECB else "CBC"}')

        encryption_key = decrypt_single_block(cipher_text=socket_to_A.recv(16), key=meta_key)

        print(f'B got encryption key : {encryption_key}')

        socket_to_A.send(start_communication.encode())

        # Jump to Receive File Data Function, passing Socket, Encryption Key and Type
        receive_and_print_file(socket_to_A, encryption_key, encryption_type)
      #  print(encryption_key)
      #  print(encryption_type)
    # In case of an Error
    except Exception as exception:

        print(exception)

    socket_to_A.close()


# File Receive and Decrypt Function
def receive_and_print_file(s, key, enc_type) -> None:
    block_count = int.from_bytes(s.recv(4), byteorder='big')

    blocks = []

    while block_count > 0:
        blocks.append(s.recv(16))
        block_count -= 1

    # Merge all Blocks into one Bytes Array and Decrypt it with chosen Decryption Method
    #   and Print it on the Screen
    #
    # If ECB chosen, Only input and key is given
    # If CBC chosen, input, key and initialization vector is given


    print(decrypt_ECB(merge(blocks), key) if enc_type == EncryptionMode.ECB else
      decrypt_CBC(merge(blocks), key, global_iv))


if __name__ == '__main__':
    main()
