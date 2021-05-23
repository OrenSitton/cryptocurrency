"""
Author: Oren Sitton
File: BlockTest.py
Python Version: 3
Description: 
"""

import logging
import pickle

def main():
    with open("Dependencies\\config.cfg", 'rb') as file:
        print(pickle.load(file))

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format="%(threadName)s [%(asctime)s]: %(message)s")
    main()
