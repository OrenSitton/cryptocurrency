"""
Author: Oren Sitton
File: Transaction.py
Python Version: 3.8
Description: 
"""
from datetime import datetime
import rsa
import hashlib


class Transaction:
    def __init__(self, input_ids, output_amounts, timestamp, input_signatures):
        """
        initiates transaction instance
        :param input_ids:
        :type input_ids:
        :param output_amounts:
        :type output_amounts:
        :param timestamp:
        :type timestamp:
        :param input_signatures:
        :type input_signatures:
        """
        self.input_ids = input_ids
        self.output_amounts = output_amounts
        self.timestamp = timestamp
        self.input_signatures = input_signatures

    def sha256_hashed(self):
        return ""
        pass


def main():
    pass


if __name__ == '__main__':
    main()
