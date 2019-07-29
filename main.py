#!/usr/bin/env python3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import base64
import hashlib
import binascii
import re
import sys

__license__ = "MIT"


def lineToFingerprint(line):
    key = base64.b64decode(line.strip().split()[1].encode('ascii'))
    fp_plain = hashlib.md5(key).hexdigest()
    return ':'.join(a+b for a,b in zip(fp_plain[::2], fp_plain[1::2]))


def insert_char_every_n_chars(string, char='\n', every=64):
    return char.join(
        string[i:i + every] for i in xrange(0, len(string), every))


def md5_fingerprint_from_pub_key(data):
    data = data.strip()

    # accept either base64 encoded data or full pub key file,
    # same as `fingerprint_from_ssh_pub_key
    if (re.search(r'^ssh-(?:rsa|dss) ', data)):
        data = data.split(None, 2)[1]

    # Python 2/3 hack. May be a better solution but this works.
    try:
        data = bytes(data, 'ascii')
    except TypeError:
        data = bytes(data)

    md5digest = hashlib.md5(data.exportKey('DER')).hexdigest()
    fingerprint = insert_char_every_n_chars(md5digest, ':', 2)
    return fingerprint


def sha256_fingerprint_from_pub_key(data):
    data = data.strip()

    # accept either base64 encoded data or full pub key file,
    # same as `fingerprint_from_ssh_pub_key
    if (re.search(r'^ssh-(?:rsa|dss) ', data)):
        data = data.split(None, 2)[1]

    # Python 2/3 hack. May be a better solution but this works.
    try:
        data = bytes(data, 'ascii')
    except TypeError:
        data = bytes(data)

    digest = hashlib.sha256(binascii.a2b_base64(data)).digest()
    encoded = base64.b64encode(digest).rstrip(b'=')  # ssh-keygen strips this
    return "SHA256:" + encoded.decode('utf-8')



def main():
    """ Main entry point of the app """
    key = rsa.generate_private_key(public_exponent=65537,
                                   key_size=4096, backend=default_backend())

    # get private key in PEM container format
    pem_private = key.private_bytes(encoding=serialization.Encoding.PEM,
                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                    encryption_algorithm=serialization.NoEncryption())

    # get public key in OpenSSH format
    pem_public_key = key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # get public key in OpenSSH format
    ssh_public_key = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                                   serialization.PublicFormat.OpenSSH)

    # decode to printable strings
    out_pem_private_key_str = pem_private.decode('utf-8')
    out_pem_public_key_str = pem_public_key.decode('utf-8')
    out_ssh_public_key_str = ssh_public_key.decode('utf-8')

    print('Private RSA key in PEM format:')
    print(out_pem_private_key_str)
    # print(lineToFingerprint(out_pem_private_key_str))
    #print(md5_fingerprint_from_pub_key(out_pem_private_key_str))

    print('Public RSA key in PEM format:')
    print(out_pem_public_key_str)

    print('Public RSA key in OpenSSH format:')
    print(out_ssh_public_key_str)
    # print(lineToFingerprint(out_ssh_public_key_str))


if __name__ == "__main__":
    """ This is executed when run from the command line """
    main()