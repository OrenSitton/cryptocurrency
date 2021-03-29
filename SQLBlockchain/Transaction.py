"""
Author: Oren Sitton
File: Transaction.py
Python Version: 3.8
Description: 
"""
import rsa
from hashlib import sha256
from datetime import datetime


class Transaction:
    def __init__(self, source, destination, date):
        """

        :param source:
        :type source: tuple
        :param destination:
        :type destination: tuple
        :param date:
        :type date:
        """
        if not isinstance(date, datetime):
            raise TypeError("Transaction.__init__: date must be of type datetime")

        self.source = source
        self.destination = destination
        self.date = date

    def verify(self):
        # TODO: add verification of signature
        pass


def main():
    pass


if __name__ == '__main__':
    main()
