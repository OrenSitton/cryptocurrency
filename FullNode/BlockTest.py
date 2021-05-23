"""
Author: Oren Sitton
File: BlockTest.py
Python Version: 3
Description: 
"""
import logging
from Dependencies import hexify
from Dependencies.__main__ import calculate_message_length

def main():
    word = "a" * 1048574
    print(calculate_message_length(word))

if __name__ == '__main__':
    main()
