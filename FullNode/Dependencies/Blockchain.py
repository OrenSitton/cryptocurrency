"""
Author: Oren Sitton
File: Blockchain.py
Python Version: 3
"""
import csv
import os

from mysql import connector

from Dependencies import Block


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
        __getitem__(block_number, prev_hash="")
            return the block(s) at the requested number
        __len__()
            calculates the length of the Blockchain's consensus chain
        append(block_number, timestamp, size, prev_hash, difficulty, nonce, merkle_root_hash, transactions, self_hash)
            appends new block to the blockchain database
        delete
            deletes block hash from sql database
        get_block_by_hash(block_hash)
            get method for blocks with certain hash
        get_block_consensus_chain(block_number)
            get method for blocks on the consensus (longest) chain

        Static Methods
        --------------
        datetime_string_posix(datetime_string)
            converts sql dateteime string to posix time
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
                            "block_number INT UNSIGNED, timestamp BIT(32),"
                            "difficulty SMALLINT, nonce VARCHAR(64) NOT NULL, prev_hash VARCHAR(64) NOT NULL,"
                            "merkle_root_hash VARCHAR(64), transactions LONGBLOB, self_hash VARCHAR(64))")

        if self.__sizeof__() == 0:
            self.append(0, 0, 0, 0, 0, "", [], "")

    def __getitem__(self, block_number, prev_hash=""):
        """
        return the block(s) at the requested number
        :param block_number: number of the block(s) to return
        :type block_number: int
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

        for x in range(len(results)):
            results[x] = Block(results[x])

        if results and not prev_hash:
            return results

        elif results:
            for result in results:
                if result[3] == prev_hash:
                    return [result]

        return None

    def __len__(self):
        """
        calculates the length of the Blockchain's consensus chain
        :return: length of the blockchain's consensus chain
        :rtype: int
        """
        self.cursor.execute("SELECT * FROM Blocks ORDER BY block_number DESC LIMIT 1")

        block = self.cursor.fetchall()

        if block:
            return block[0][1]
        else:
            return 0

    def __sizeof__(self):
        self.cursor.execute("SELECT * FROM Blocks")

        return len(self.cursor.fetchall())

    def append(self, block_number, timestamp, difficulty, nonce, previous_hash, merkle_root_hash, transactions,
               self_hash):
        """
        appends new block to the blockchain database
        :param block_number: number of block (distance from genesis block)
        :type block_number: int
        :param timestamp: time block was created (posix time)
        :type timestamp: int
        :param difficulty: difficulty of block (length of hash zero prefix)
        :type difficulty: int
        :param nonce: block nonce used to achieve targeted difficulty
        :type nonce: int
        :param previous_hash:
        :type previous_hash:
        :param merkle_root_hash: root of transactions merkle tree
        :type merkle_root_hash: str
        :param transactions: list of transactions to be included in the block
        :type transactions: list
        :param self_hash: hash of the block
        :type self_hash: str
        """
        for x in range(len(transactions)):
            transactions[x] = transactions[x].network_format()
        t = ""
        for x in transactions:
            t += "{},".format(x)
        t = t[:-1]
        self.cursor.execute("INSERT INTO Blocks (block_number, timestamp, difficulty, nonce, prev_hash,"
                            " merkle_root_hash, transactions, self_hash) VALUES ({}, {}, {}, \"{}\", \"{}\","
                            "\"{}\", \"{}\", \"{}\")".format(block_number, timestamp, difficulty, nonce, previous_hash,
                                                             merkle_root_hash, t, self_hash))
        self.db.commit()

    def append_block(self, block):
        """

        :param block:
        :type block: Block
        :return:
        :rtype:
        """
        # TODO: implement
        pass

    def delete(self, block_hash):
        """
        deletes block from sql database
        :param block_hash: hash of block to delete
        :type block_hash: str
        """
        self.cursor.execute("DELETE FROM Blocks WHERE self_hash={}".format(block_hash))

    def export(self, directory, first_block_number, last_block_number):
        """

        :param directory:
        :type directory:
        :param first_block_number:
        :type first_block_number:
        :param last_block_number:
        :type last_block_number:
        :return:
        :rtype:
        """
        # TODO: fix to just export entire database, not certain blocks or consensus chain
        current_directory = os.getcwd()
        os.chdir(directory)

        self.cursor.execute("SELECT * FROM Blocks")
        results = self.cursor.fetchall()

        with open('blockchain.csv', 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["block_number", "time_created", "prev_hash", "difficulty", "nonce",
                             "merkle_root_hash", "transactions", "self_hash"])
            for i in range(first_block_number, last_block_number + 1):
                try:
                    block = self[i]
                    result_array = [block.block_number, block.timestamp, block.prev_hash, block.difficulty, block.nonce, block.merkle_root_hash, block.transactions.decode(), block.self_hash]
                    writer.writerow(result_array)
                except IndexError:
                    pass

        os.chdir(current_directory)

    def get_block_by_hash(self, block_hash):
        """
        get method for block with certain hash
        :param block_hash: block hash
        :type block_hash: str
        :return: block with hash block_hash
        :rtype: Block
        """
        self.cursor.execute("SELECT * FROM Blocks WHERE self_hash={}".format(block_hash))
        result = self.cursor.fetchall()

        if result:
            return Block(result[0])
        else:
            return None

    def get_block_consensus_chain(self, block_number):
        """
        get method for blocks on the consensus (longest) chain
        :param block_number: block number of requested block
        :type block_number: int
        :return: requested block
        :rtype: Block
        :raises: IndexError: block number is not within range
        :raises: TypeError: expected block number to be of type int
        """
        if block_number < 1 or block_number > self.__len__():
            raise IndexError("Blockchain.get_blocks: block number not within range")
        elif not isinstance(block_number, int):
            raise TypeError("Blockchain.get_blocks: expected block number to be of type int")

        if block_number < self.__len__() - 1:
            return self.__getitem__(block_number)[0]

        self.cursor.execute("SELECT * FROM Blocks WHERE block_number={}".format(block_number))

        results = self.cursor.fetchall()

        for x in range(len(results)):
            results[x] = Block(results[x])

        if len(results) == 1:
            return results[0]
        else:
            minimum_posix = results[0]
            for result in results:
                if result.timestamp < minimum_posix.timestamp:
                    minimum_posix = result
            if block_number == self.__len__():
                return minimum_posix
            else:
                return self.get_block_by_hash(minimum_posix.prev_hash)

    def get_block_by_previous_hash(self, previous_hash):
        """

        :param previous_hash:
        :type previous_hash:
        :return:
        :rtype: Block
        """
        self.cursor.execute("SELECT * FROM Blocks WHERE prev_hash={}".format(previous_hash))
        result = self.cursor.fetchall()

        if result:
            return Block(result[0])
        else:
            return None


def main():
    Blockchain().export("C:\\Users\\Orens\\Desktop", 10, 20)
    pass


if __name__ == '__main__':
    main()
