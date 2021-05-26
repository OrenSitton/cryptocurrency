"""
Author: Oren Sitton
File: GenerateKeys.py
Python Version: 3
Description: 
"""

import errno

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
import os


def main():
    key = RSA.generate(1024)
    with open('privkey.der', 'wb') as f:
        f.write(key.exportKey('DER'))
    with open('pubkey.der', 'wb') as f:
        f.write(key.publickey().exportKey('DER'))

    with open('pubkey.der', 'rb') as f:
        key = RSA.importKey(f.read())
        print("Public Key: {}".format(key.publickey().exportKey('DER').hex()))
        pass
    with open('privkey.der', 'rb') as f:
        key = RSA.import_key(f.read())
        print("Private Key: {}".format(key.exportKey('DER').hex()))

    os.remove('privkey.der')
    os.remove('pubkey.der')

    pass


if __name__ == '__main__':
    main()
