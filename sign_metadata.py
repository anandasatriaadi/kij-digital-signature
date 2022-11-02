from curses import meta
from inspect import signature
import os
from Crypto.PublicKey import RSA
from hashlib import sha512
from PyPDF2 import PdfFileReader, PdfFileMerger, PdfReader
import regex as re

PRIVATE_KEY = 'private.pem'
PUBLIC_KEY = 'public.pem'

# Generate Private & Public Keys
def generate_keys():
    key = RSA.generate(1024)
    private_key = key.exportKey()
    public_key = key.publickey().exportKey()

    with open(PRIVATE_KEY, 'wb') as f:
        f.write(private_key)

    with open(PUBLIC_KEY, 'wb') as f:
        f.write(public_key)

# Add signature metadata to file
def modify_metadata(in_filename, out_filename, metadata_new):
    file_in = open(in_filename, 'rb')
    pdf_reader = PdfFileReader(file_in)
    metadata = pdf_reader.getDocumentInfo()

    # Duplicate metadata
    metadata_cp = metadata.copy()

    for key, value in metadata_new.items():
        metadata_cp[key] = value

    pdf_merger = PdfFileMerger()
    pdf_merger.append(file_in)
    pdf_merger.addMetadata(metadata_cp)
    
    repaired_file = out_filename

    file_out = open(repaired_file, 'wb')
    pdf_merger.write(file_out)

    file_in.close()
    file_out.close()

# Read file as text
def read_file(filename):
    with open(filename, 'rb') as f:
        return str(f.read())

# Read metadata
def read_metadata(filename, metadata_name):
    file_text = read_file(filename)
    matches = re.finditer(rf"(?<={metadata_name} \().*?(?=\))", read_file(filename), re.MULTILINE)
    for match in matches:
        val = match.group()
        return val

# Calculate hash
def calculate_hash(filename):
    with open(filename, 'rb') as f:
        file_size = os.path.getsize(filename)
        print(f"[!] File size: {file_size} bytes")

        sha512_hash = sha512()
        while chunk := f.read(4096):
            sha512_hash.update(chunk)
        hash = int.from_bytes(sha512_hash.digest(), byteorder='big')
        return hash

# Encrypt hash
def encrypt_hash(hash, KEY):
    with open(KEY, 'r') as f:
        key = RSA.importKey(f.read())
        signature = pow(hash, key.d, key.n)
        return signature

def decrypt_signature(signature, KEY):
    with open(KEY, 'r') as f:
        key = RSA.importKey(f.read())
        decrypted_signature = pow(signature, key.e, key.n)
        return decrypted_signature

# Sign file
def sign_file(filename):
    print("[!] Signing file...")
    # Cleaning signature metadata
    file_ext = os.path.splitext(filename)[1]
    original_file = f"{os.path.splitext(filename)[0]}_original{file_ext}"

    modify_metadata(filename, original_file, {'/Signature': ''})
    
    hash = calculate_hash(original_file)
    print(f"[!] Hash: {hash}")
    signature = encrypt_hash(hash, PRIVATE_KEY)
    print(f"[!] Signature: {signature}")

    signed_filename = f"{os.path.splitext(filename)[0]}_signed{file_ext}"

    modify_metadata(original_file, signed_filename, {'/Signature': str(signature)})

# Verify file
def verify_file(filename):
    print("[!] Verifying file...")

    # Cleaning signature metadata
    file_ext = os.path.splitext(filename)[1]
    original_file = f"{os.path.splitext(filename)[0]}_original{file_ext}"

    modify_metadata(filename, original_file, {'/Signature': ''})

    signature_text = read_metadata(filename, "/Signature")
    signature = int(signature_text)
    print(f"[!] signature: {signature}")

    hash = calculate_hash(original_file)
    print(f"[!] Hash: {hash}")
    decrypted_signature = decrypt_signature(signature, PUBLIC_KEY)
    print(f"[!] decrypted_signature: {decrypted_signature}")

    return decrypted_signature == hash

if __name__ == '__main__':
    # Check for keys availability
    if(not os.path.exists(PRIVATE_KEY) or not os.path.exists(PUBLIC_KEY)):
        print("[!] Generating keys...")
        generate_keys()
        print("[!] Keys generated!")

    # ls
    print("[+] Files in current directory:")
    for file in os.listdir():
        print(f"\t> {file}")

    # Read Input File
    filename = input("[>] Enter file name: ")
    # filename = "Invoice.pdf"

    # sign file
    sign_file(filename)

    print("\n\n")

    # verify signed file
    file_ext = os.path.splitext(filename)[1]
    signed_filename = f"{os.path.splitext(filename)[0]}_signed{file_ext}"
    if(verify_file(signed_filename)):
        print("[+] File verified! SIGNATURE MATCHED!")
    else:
        print("[!] File not verified! SIGNATURE NOT MATCHED!")