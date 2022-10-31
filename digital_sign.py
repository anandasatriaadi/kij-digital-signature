import os
from Crypto.PublicKey import RSA
from hashlib import sha512

PRIVATE_KEY = 'private.pem'
PUBLIC_KEY = 'public.pem'

# Sign file
def sign_file(filename):
    with open(filename, 'rb') as f:
        file_size = os.path.getsize(filename)
        print(f"[!] File size: {file_size} bytes")

        sha512_hash = sha512()
        while chunk := f.read(4096):
            sha512_hash.update(chunk)
        hash = int.from_bytes(sha512_hash.digest(), byteorder='big')
        print(f"[!] Hash: {hash}")

        with open(PRIVATE_KEY, 'r') as private_key_file:
            private_key = RSA.importKey(private_key_file.read())
            signature = pow(hash, private_key.d, private_key.n)
            print(f"[!] Signature: {signature}")

            f.seek(0)

            file_type = os.path.splitext(filename)[1]
            signed_filename = f"{os.path.splitext(filename)[0]}_signed{file_type}"

            with open(signed_filename, 'wb') as signed_f:
                while chunk := f.read(4096):
                    signed_f.write(chunk)

                signed_f.write(signature.to_bytes(128, byteorder='big'))

            print("\n\n\n")

# Verify file
def verify_file(filename):
    with open(filename, 'rb') as f:
        file_size = os.path.getsize(filename)
        print(f"[!] File size: {file_size} bytes")

        real_size = file_size - 128
        counter = 0
        chunk = b''
        sha512_hash = sha512()
        if(real_size <= 4096):
            chunk = f.read(real_size)
            sha512_hash.update(chunk)
        else:
            chunk = f.read(4096)
            while chunk:
                sha512_hash.update(chunk)

                counter += 1
                if((counter + 1) * 4096 < real_size):
                    chunk = f.read(4096)
                else:
                    chunk = f.read(real_size - counter * 4096)
                    break

            sha512_hash.update(chunk)

        hash = int.from_bytes(sha512_hash.digest(), byteorder='big')
        print(f"[!] Hash: {hash}")

        signature = int.from_bytes(f.read(128), byteorder='big')
        print(f"[!] Signature: {signature}")
        print("\n")

        with open(PUBLIC_KEY, 'r') as public_key_file:
            public_key = RSA.importKey(public_key_file.read())
            decrypted_signature = pow(signature, public_key.e, public_key.n)
            print(f"[!] Decrypted signature: {decrypted_signature}")

            if(decrypted_signature == hash):
                return True
            else:
                return False

if __name__ == '__main__':
    # ls
    print("[+] Files in current directory:")
    for file in os.listdir():
        print(f"\t> {file}")

    # Read Input File
    filename = input("Enter file name: ")

    # Sign file
    sign_file(filename)

    # Verify file
    verif_result = verify_file(f"{os.path.splitext(filename)[0]}_signed{os.path.splitext(filename)[1]}")
    if(verif_result):
        print("[!] CHECK SIGNATURE: VERIFIED")
    else:
        print("[!] CHECK SIGNATURE: NOT VERIFIED")