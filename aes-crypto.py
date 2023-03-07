import argparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode


def bytes_to_string(bytes):
    return b64encode(bytes).decode('utf-8')


def string_to_bytes(bytes):
    return b64decode(bytes)


def get_key(key_path):
    f = open(key_path, "r")
    key = f.read()
    f.close()
    return key


def generate_key(key_path):
    key = get_random_bytes(16)
    f = open(key_path, "w")
    f.write(bytes_to_string(key))
    f.close()


def encrypt(key_path, src_path, dst_path):
    key = get_key(key_path)
    cipher = AES.new(string_to_bytes(key), AES.MODE_EAX)
    file_in = open(src_path, "r")
    data = file_in.read()
    ciphertext = cipher.encrypt(data.encode('utf-8'))
    file_out = open(dst_path, "w")
    [file_out.write(x)
     for x in (bytes_to_string(cipher.nonce), "\n", bytes_to_string(ciphertext))]
    file_out.close()


def decrypt(key_path, src_path, dst_path):
    key = get_key(key_path)
    file_in = open(src_path, "r")
    nonce, ciphertext = [line.rstrip('\n') for line in file_in.readlines()]
    cipher = AES.new(string_to_bytes(key), AES.MODE_EAX,
                     string_to_bytes(nonce))
    plaintext = cipher.encrypt(string_to_bytes(ciphertext))
    f = open(dst_path, 'w')
    f.write(plaintext.decode("utf-8"))


def main(args):
    state = args.state
    src_path = args.src_path
    dst_path = args.dst_path
    key_path = args.key_path
    match state:
        case 1:
            generate_key(key_path)
        case 2:
            encrypt(key_path, src_path, dst_path)
        case 3:
            decrypt(key_path, src_path, dst_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        '-s', '--state', choices=[1, 2, 3], required=True, help="Some option, where\n"
        " 1 = Generate Key\n"
        " 2 = Encrypt\n"
        " 3 = Decrypt\n",
        type=int
    )
    parser.add_argument("-dp", "--dst_path", )
    parser.add_argument("-sp", "--src_path", )
    parser.add_argument("-kp", "--key_path", required=True)
    args = parser.parse_args()

    if ((args.state == 3 or args.state == 2) and (args.src_path == None or args.dst_path == None)):
        parser.error("You need to supply data path")

    main(args)
