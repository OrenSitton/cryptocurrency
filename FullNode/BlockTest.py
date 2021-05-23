"""
Author: Oren Sitton
File: BlockTest.py
Python Version: 3
Description: 
"""
import logging
from Dependencies import hexify
from Dependencies.__main__ import calculate_message_length
import pickle

def main():
    with open("Dependencies\\config.cfg", 'rb') as file:
        print(pickle.load(file))

if __name__ == '__main__':
    main()
