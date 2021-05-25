"""
Author: Oren Sitton
File: tmp.py
Python Version: 3
Description: 
"""
import pickle


def main():
    configuration = {
        "server ip address": "0.0.0.0",
        "server port": 8333,
        "public key": "Dependencies\\pubkey.der",
        "private key": "Dependencies\\privkey.der"
    }
    with open("Dependencies\\config.cfg", 'wb') as file:
        pickle.dump(configuration, file)
    pass


if __name__ == '__main__':
    main()
# TODO: change keys to strings