"""
Author: Oren Sitton
File: configure.py
Python Version: 3.8
Description: configure config.txt file for full node
"""
from pickle import dump


def main():
    configuration = {
        "ip address": "localhost",
        "port": 8333,
        "seed address": "localhost",
        "seed port": 8666,
        "sql address": "localhost",
        "sql port": 3306
    }
    with open("config.txt", "wb") as file:
        dump(configuration, file)


if __name__ == '__main__':
    main()
