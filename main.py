import os
from Crypto.PublicKey import RSA
from hashlib import sha512

keyPair = RSA.generate(bits=1024)
print(f"Public key:  (n={keyPair.n}, e={keyPair.e})")
print(f"Private key: (n={keyPair.n}, d={keyPair.d})")

# ========================================================================
#   Encrypt
# ========================================================================
filename_full = input("Enter a file name: ")
if not os.path.isfile(filename_full):
    print("File not found")
    exit()

filename = os.path.splitext(filename_full)[0]
file_ext = os.path.splitext(filename_full)[1]

with open(filename_full, 'rb') as f:
    file_size = os.path.getsize(filename_full)
    print(f"File size: {file_size} bytes")

    sha512_hash = sha512()
    while chunk := f.read(4096):
        sha512_hash.update(chunk)
    hash = int.from_bytes(sha512_hash.digest(), byteorder='big')
    print(f"Hash: {hash}")
    signature = pow(hash, keyPair.d, keyPair.n)
    print(f"Signature: {signature}")

    f.seek(0)
    signed_filename = f"{filename}_signed{file_ext}"

    with open(signed_filename, 'wb') as signed_f:
        while chunk := f.read(4096):
            signed_f.write(chunk)

        signed_f.write(signature.to_bytes(128, byteorder='big'))

    print("\n\n\n")


# ========================================================================
#   Verify
# ========================================================================

signed_file = f"{filename}_signed{file_ext}"
with open(signed_file, 'rb') as f:
    file_size = os.path.getsize(signed_file)
    print(f"File size: {file_size} bytes")

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
    print(f"Hash: {hash}")

    signature = int.from_bytes(f.read(128), byteorder='big')
    print(f"Signature: {signature}")

    decrypted_signature = pow(signature, keyPair.e, keyPair.n)
    print(f"Decrypted signature: {decrypted_signature}")

    if hash == decrypted_signature:
        print("Signature is valid")
    else:
        print("Signature is invalid")
