"""
Author: Oren Sitton
File: tmp.py
Python Version: 3
Description: 
"""
import pickle

def main():
    dictionary = {
        "node ip address":"0.0.0.0",
        "node port":8333,
        "wallet ip address":"0.0.0.0",
        "wallet port":8999,
        "seed address":"172.16.16.140",
        "seed port":8666,
        "sql address": "127.0.0.1",
        "sql user": "root",
        "sql password":"root"
    }

    with open("Dependencies\\config.cfg", 'wb') as file:
        pickle.dump(dictionary, file)
    pass


if __name__ == '__main__':
    main()
