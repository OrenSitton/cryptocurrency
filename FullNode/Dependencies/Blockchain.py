"""
Author: Oren Sitton
File: Blockchain.py
Python Version: 3
"""

import csv
import os
from mysql import connector
from datetime import datetime


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
        self.db = connector.connect(
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
                            "hash VARCHAR(64) NOT NULL, difficulty SMALLINT, nonce MEDIUMINT, "
                            "merkle_root_hash VARCHAR(64), transactions LONGBLOB, self_hash VARCHAR(64))")

        if len(self) == 0:
            self.append(0, 1, 0, "", 0, 0, "", "", "")

    def __getitem__(self, block_number, prev_hash=""):
        """
        return the block(s) at the requested number
        :param index: number of the block(s) to return
        :type index: int
        :return: requested block(s)
        :rtype: tuple
        :raises: IndexError: block number is not within range
        :raises: TypeError: expected block number to be of type int
        """
        if block_number < 1 or block_number > self.__len__():
            raise IndexError("Blockchain.__getitem__: index out of range")
        elif not isinstance(block_number, int):
            raise TypeError("Blockchain.__getitem__: expected block number to be of type int")

        self.cursor.execute("SELECT * FROM Blocks WHERE block_number={}".format(block_number))

        results = self.cursor.fetchall()

        if results and not prev_hash:
            maximum_depth = results[0]
            for result in results:
                if self.get_depth(result[4]) > self.get_depth(maximum_depth[4]):
                    maximum_depth = result

            return maximum_depth

        elif results:
            for result in results:
                if result[4] == prev_hash:
                    return result

        return None

    def __len__(self):
        """
        return the length of the Blockchain's consensus chain
        :return: length of the blockchain's consensus chain
        :rtype: int
        """
        self.cursor.execute("SELECT * FROM Blocks ORDER BY block_number DESC LIMIT 1")

        block = self.cursor.fetchall()

        if block:
            return block[1]
        else:
            return 0

    def append(self, block_number, timestamp, size, prev_hash, difficulty, nonce, merkle_root_hash, transactions,
               self_hash):
        """
        appends new block to the blockchain database
        :param block_number: number of block (distance from genesis block)
        :type block_number: int
        :param timestamp: time block was created (posix time)
        :type timestamp: int
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
        :param self_hash: hash of the block
        :type self_hash: str
        """
        datetime_object = datetime.fromtimestamp(timestamp)
        timestamp = "{}-{}-{} {}:{}:{}".format(datetime_object.year, datetime_object.month, datetime_object.day,
                                               datetime_object.hour, datetime_object.minute, datetime_object.second)
        self.cursor.execute("INSERT INTO Blocks (block_number, time_created, size, hash, difficulty, nonce, "
                            "merkle_root_hash, transactions, self_hash) VALUES ({}, \'{}\', {}, \"{}\", {}, {}, "
                            "\"{}\", \"{}\", \"{}\")".format(block_number, timestamp, size, prev_hash, difficulty,
                                                             nonce, merkle_root_hash, transactions, self_hash))
        self.db.commit()

    def export(self, directory):
        """
        exports sql database into a csv file
        :param directory: directory to save database into
        :type directory: str
        """
        # TODO: add error handling
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

    def get_depth(self, block_hash):
        """
        calculates the depth of the block with the given hash
        :param block_hash: hash of block
        :type block_hash: str
        :return: depth of block
        :rtype: int
        :raises: TypeError: expected block_hash to be of type str
        """
        if not isinstance(block_hash, str):
            raise TypeError("Blockchain.get_depth: expected block hash to be of type str")
        # TODO: implement function

    def get_blocks(self, block_number):
        """
        get method for blocks from all chains
        :param block_number: requested block number
        :type block_number: int
        :return: all blocks with requested block number
        :rtype: tuple
        :raises: IndexError: block number is not within range
        :raises: TypeError: expected block number to be of type int
        """
        if block_number < 1 or block_number > self.__len__():
            raise IndexError("Blockchain.get_blocks: block number not within range")
        elif not isinstance(block_number, int):
            raise TypeError("Blockchain.get_blocks: expected block number to be of type int")

        self.cursor.execute("SELECT * FROM Blocks WHERE block_number={}".format(block_number))

        results = self.cursor.fetchall()

        return results
    
    def get_block_consensus_chain(self, block_number):
        """
        get method for blocks on the consensus (longest) chain
        :param block_number: block number of requested block
        :type block_number: int
        :return: requested block
        :rtype: tuple
        :raises: IndexError: block number is not within range
        :raises: TypeError: expected block number to be of type int
        """
        if block_number < 1 or block_number > self.__len__():
            raise IndexError("Blockchain.get_blocks: block number not within range")
        elif not isinstance(block_number, int):
            raise TypeError("Blockchain.get_blocks: expected block number to be of type int")

        # TODO: implement function


def main():
    print(Blockchain())
    pass


if __name__ == '__main__':
    main()
