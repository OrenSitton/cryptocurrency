"""
Author: Oren Sitton
File: test.py
Python Version: 3
Description: 
"""
from Dependencies.methods import *

def main():
    print(hexify_string("oren"))
    print(bytes.fromhex(hexify_string("oren")).decode())
    pass


if __name__ == '__main__':
    main()
