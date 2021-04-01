"""
Author: Oren Sitton
File: Blockchain.py
Python Version: 3
Description: 
"""
import csv
import os
import mysql.connector
import datetime
from hashlib import sha256


class Blockchain:
    """
        Blockchain class, implements Blockchain based on a MySQL server

        Attributes
        ----------
        host : str
            ip address of the MySQL server (default "localhost")
        user : str
            username for the MySQL server (default "root")
        password : str
            password for the MySQL server (default "root")
        db : MySQL connector
            connector to the MySQL database
        cursor : MySQL cursor
            cursor to point to the MySQL database

        Methods
        -------
        __init__(host="localhost", user="root", password="root")
            initializes the Blockchain database (if not initialized), the MySQl connector and the MySQL cursor
        append(value)

        __len__()

        __str__()

        __getitem__(index)

        export(directory)


        """

    def __init__(self, host="localhost", user="root", password="root"):
        """
        initiator for Blockchain objects
        :param host: host address of MySQL server, default 127.0.0.1
        :type host: str
        :param user: MySQL server username
        :type user: str
        :param password: MySQL server password
        :type password: str
        """

        # connect to MySQL server
        self.db = mysql.connector.connect(
            host=host,
            user=user,
            passwd=password,
        )

        # initiate database cursor
        self.cursor = self.db.cursor()

        # create Blockchains database if it doesn't exist yet
        self.cursor.execute("CREATE DATABASE if not EXISTS Blockchain")

        # set cursor's database to Blockchain
        self.db.database = "Blockchain"

        # create Block table in Blockchain database if it doesn't exist yet
        self.cursor.execute("CREATE TABLE if not EXISTS Blocks (id int UNSIGNED PRIMARY KEY AUTO_INCREMENT, "
                            "block_number INT UNSIGNED, time_created TIMESTAMP, size MEDIUMINT, "
                            "prev_hash VARCHAR(256) NOT NULL, difficulty SMALLINT, nonce MEDIUMINT, "
                            "merkle_root_hash VARCHAR(256), transactions LONGBLOB)")

    def append(self, block_number, timestamp, size, prev_hash, difficulty, nonce, merkle_root_hash, transactions):
        """
        appends new block to the end of the blockchain
        :param block_number: number of block (distance from genesis block)
        :type block_number: int
        :param timestamp: time block was created
        :type timestamp: str
        :param size: size of the block in bits
        :type size: int
        :param prev_hash: hash of the previous block
        :type prev_hash: str
        :param difficulty: difficulty of block (length of hash zero prefix)
        :type difficulty: int
        :param nonce: block nonce used to achieve targeted difficulty
        :type nonce: int
        :param merkle_root_hash: root of transactions merkle tree
        :type merkle_root_hash: str
        :param transactions: list of transactions to be included in the block
        :type transactions: str
        """

        self.cursor.execute("INSERT INTO Blocks (block_number, time_created, size, prev_hash, difficulty, nonce, "
                            "merkle_root_hash, transactions) VALUES ({}, \'{}\', {}, \"{}\", {}, {}, \"{}\", \"{}\")"
                            .format(block_number, timestamp, size, prev_hash, difficulty, nonce, merkle_root_hash,
                                    transactions))
        self.db.commit()

    def __len__(self):
        """
        return the length of the Blockchain
        :return: length of the blockchain
        :rtype: int
        """
        self.cursor.execute("SELECT * FROM Blocks")

        return len(self.cursor.fetchall())

    def __str__(self):
        """
        returns the string representation of the blockchain
        :return: string representation of the blockchain
        :rtype: str
        """
        if self.__len__():
            string_repr = ""

            for x in range(self.__len__() - 1, 0, -1):
                string_repr += "Data: {}\nHash:  {}\n ↓↓\n".format(self[x], self[x][5])

            string_repr += "Data: {}\nHash:  Genesis".format(self[0])

            return string_repr

        else:
            return ""

    def __getitem__(self, index):
        """
        return the item at the index requested (starting from 0)
        :param index: index of the item to return
        :type index: int
        :return: requested block
        :rtype: (str, str)
        """
        if index < 0 or index >= self.__len__():
            raise IndexError("Blockchain.__getitem__: index out of range")
        elif not isinstance(index, int):
            raise TypeError("Blockchain.__getitem__: index must be an integer")

        index += 1
        self.cursor.execute("SELECT * FROM Blocks WHERE id={}".format(index))

        results = self.cursor.fetchall()

        if len(results):
            return results[0]

    def export(self, directory):
        current_directory = os.getcwd()
        os.chdir(directory)

        filename = "Blockchain"

        if os.path.isfile(filename + ".csv"):

            filename += "(1)"
            addition = 1

            while os.path.isfile(filename + ".csv"):
                addition += 1
                filename = filename[:11] + str(addition) + ")"

        filename += ".csv"
        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["id", "data", "prev_hash"])

            for gen in range(self.__len__()):
                writer.writerow([gen + 1, self[gen][0], self[gen][1]])

        os.chdir(current_directory)


def main():
    pass


if __name__ == '__main__':
    main()
