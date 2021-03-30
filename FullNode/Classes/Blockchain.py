"""
Author: Oren Sitton
File: Blockchain.py
Python Version: 3
Description: 
"""
import csv
import os
import mysql.connector
from hashlib import sha256


class Blockchain:
    def __init__(self, host="localhost", user="root", passwd="root"):
        """
        initiator for Blockchain objects
        :param host: host address of MySQL server, default 127.0.0.1
        :type host: str
        :param user: MySQL server username
        :type user: str
        :param passwd: MySQL server password
        :type passwd: str
        """

        #TODO: add date & time column to SQL db

        # connect to MySQL server
        self.db = mysql.connector.connect(
            host=host,
            user=user,
            passwd=passwd,
        )

        # initiate database cursor
        self.cursor = self.db.cursor()

        # create Blockchains database if it doesn't exist yet
        self.cursor.execute("CREATE DATABASE if not EXISTS Blockchain")

        # set cursor's database to Blockchain
        self.db.database = "Blockchain"

        # create Block table in Blockchain database if it doesn't exist yet
        self.cursor.execute("CREATE TABLE if not EXISTS Block (id int UNSIGNED PRIMARY KEY AUTO_INCREMENT,"
                            " data LONGTEXT, prev_hash VARCHAR(64) NOT NULL)")

    def __len__(self):
        """
        return the length of the Blockchain
        :return: length of the blockchain
        :rtype: int
        """
        self.cursor.execute("SELECT * FROM Block")

        return len(self.cursor.fetchall())

    def append(self, value):
        """
        add new block to the blockchain
        :param value: data to store in the block
        :type value: object
        :return: none
        :rtype: None
        """
        # request most recent block in blockchain
        self.cursor.execute("SELECT prev_hash, data FROM Block ORDER BY id DESC LIMIT 1")

        results = self.cursor.fetchall()

        prev_hash = ""
        if len(results):  # if previous block exists, calculate previous hash
            bytes_data = bytes(results[0][0] + results[0][1], "UTF-8")
            prev_hash = sha256(bytes_data).hexdigest()

        # add new block containing data & hash into the blockchain
        self.cursor.execute("INSERT INTO Block (prev_hash, data) VALUES (%s, %s)", (prev_hash, value))
        self.db.commit()

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
        self.cursor.execute("SELECT prev_hash, data FROM Block WHERE id={}".format(index))

        results = self.cursor.fetchall()

        if len(results):
            return results[0][1], results[0][0]

    def __str__(self):
        """
        returns the string representation of the blockchain
        :return: string representation of the blockchain
        :rtype: str
        """
        if self.__len__():
            string_repr = ""

            for x in range(self.__len__() - 1, 0, -1):
                string_repr += "Value: {}\nHash:  {}\n ↓↓\n".format(self[x][0], self[x][1])

            string_repr += "Value: {}\nHash:  Genesis".format(self[0][0])

            return string_repr

        else:
            return ""

    def export(self, directory):
        current_directory = os.getcwd()
        os.chdir(directory)

        filename = "Blockchain"

        if os.path.isfile(filename + ".csv"):

            filename += "(1)"
            addition = 1

            while(os.path.isfile(filename + ".csv")):
                addition += 1
                filename = filename[:11] + str(addition) + ")"


        filename += ".csv"
        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["id", "data", "prev_hash"])

            for gen in range(self.__len__()):
                writer.writerow([gen + 1, self[gen][0], self[gen][1]])


def main():
    os = Blockchain()
    os.export("C:\\Users\\Orens\\Documents\\Cyber Project\\Cryptocurrency\\SQL-Blockchain")
    pass


if __name__ == '__main__':
    main()
