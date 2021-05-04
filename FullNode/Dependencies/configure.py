"""
Author: Oren Sitton
File: configure.py
Python Version: 3
Description: configure config.txt file for full node
"""
from pickle import dump


def main():
    configuration = {
        "ip address": "192.0",
        "port": 8333,
        "seed address": "localhost",
        "seed port": 8666,
        "sql address": "localhost",
        "sql user": "root",
        "sql password": "root",
        "default difficulty": 22,
        "block reward": 10,
        "difficulty change count": 2016,
        "public key": "30819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001 "
    }
    with open("config.txt", "wb") as file:
        dump(configuration, file)


if __name__ == '__main__':
    main()
