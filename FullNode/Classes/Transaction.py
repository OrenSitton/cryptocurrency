"""
Author: Oren Sitton
File: Transaction.py
Python Version: 3.8
Description: 
"""
from datetime import datetime
from hashlib import sha256


class Transaction:
    """
    Transaction class, implements blemflark transactions that can be converted to network protocol format

    Attributes
    ----------
    timestamp : datetime
        time of the transaction
    inputs : list[(block number, transaction number, signature)]
        list of transaction sources & signatures
    outputs : list[(public key, amount)]
        list of transaction output amounts & destinations

    Methods
    -------
    __init__(timestamp, inputs, outputs)
        initializes transaction instance
    __str__()
        returns string format of transaction
    sha256_hash()
        calculates sha256 hash of the transaction, per the Blemflark protocol
    network_format()
        converts Transaction object into a hexadecimal string of the transaction in the network protocol format

    Static Methods
    --------------
    from_network_format(hex_transaction)
        creates a Transaction object from a string, containing a transaction in the network protocol format
    hexify(number, length)
        calculates hexadecimal value of the number, with prefix zeroes to match length
    """
    def __init__(self, timestamp, inputs, outputs):
        """
        initiates transaction instance
        :param timestamp: time of the transaction
        :type timestamp: datetime
        :param inputs: list of transactions & signatures, as tuples (transaction block number, transaction number,
                       sender's signature)
        :type inputs: list
        :param outputs: list of output keys & amount per key, as tuples (output key, amount)
        :type outputs: list
        """
        if not (isinstance(timestamp, int) or isinstance(timestamp, datetime)):
            raise TypeError("Transaction.__init__(timestamp, inputs, outputs): expected timestamp to be of type int "
                            "or datetime")
        # TODO: error handling, check that inputs and outputs list are valid

        if isinstance(timestamp, int):
            self.timestamp = datetime.fromtimestamp(timestamp)
        elif isinstance(timestamp, datetime):
            self.timestamp = timestamp

        self.inputs = inputs
        self.outputs = outputs

    def __str__(self):
        """
        returns string format of transaction
        :return: string format of transaction
        :rtype: str
        """
        string_representation = "Time Created:{}\nInputs:\n".format(self.timestamp)
        for inp in self.inputs:
            string_representation += "{}.{}  |  {}\n".format(inp[0], inp[1], inp[2])
        string_representation += "Outputs:\n"
        for output in self.outputs:
            string_representation += "{}  |  {}\n".format(output[1], output[0])
        return string_representation[:-1]

    def sha256_hash(self):
        """
        calculates sha256 hash of the transaction, per the Blemflark protocol
        :return: sha256 hash of the transaction, as a hexadecimal string
        :rtype: str
        """
        return sha256(self.network_format().encode('utf-8')).hexdigest()

    def network_format(self):
        """
        converts Transaction object into a hexadecimal string of the transaction in the network protocol format
        :return: hexadecimal transaction in the network protocol format
        :rtype: str
        """
        message = ""

        time_created = Transaction.hexify(int(self.timestamp.timestamp()), 8)

        inputs_amount = Transaction.hexify(len(self.inputs), 1)

        outputs_amount = Transaction.hexify(len(self.outputs), 1)

        message = "{}{}{}".format(time_created, inputs_amount, outputs_amount)

        for inp in self.inputs:
            input_block_number = Transaction.hexify(inp[0], 6)
            input_transaction_number = Transaction.hexify(inp[1], 2)
            signature = inp[2]

            message += input_block_number + input_transaction_number + signature

        for output in self.outputs:
            output_address = output[0]
            amount = Transaction.hexify(output[1], 4)

            message += output_address + amount
        message = message.replace(" ", "")
        return message

    @staticmethod
    def from_network_format(hex_transaction):
        """
        creates a Transaction object from a string, containing a transaction in the network protocol format
        :param hex_transaction: transaction in network protocol format
        :type hex_transaction: str
        :return: Transaction object
        :rtype: Transaction
        """
        if len(hex_transaction) < 10:
            raise ValueError("Transaction.from_network_format(hex_transaction): hexadecimal value does not represent "
                             "valid transaction")
        time_created = int(hex_transaction[0:8], 16)
        amount_of_inputs = int(hex_transaction[8:9], 16)
        amount_of_outputs = int(hex_transaction[9:10], 16)

        if len(hex_transaction) != 10 + amount_of_inputs * 264 + amount_of_outputs * 328:
            raise ValueError("Transaction.from_network_format(hex_transaction): hexadecimal value does not represent "
                             "valid transaction")

        hex_transaction = hex_transaction[10:]

        input_ids = []
        input_signatures = []
        output_amounts = []

        for i in range(amount_of_inputs):
            input_block_number = int(hex_transaction[0:6], 16)
            input_transaction_number = int(hex_transaction[6:8], 16)
            signature = hex_transaction[8: 264]

            input_ids.append((input_block_number, input_transaction_number, signature))
            hex_transaction = hex_transaction[264:]

        for i in range(amount_of_outputs):
            output_address = hex_transaction[0:324]
            output_amount = int(hex_transaction[324: 328], 16)

            output_amounts.append((output_address, output_amount))
            hex_transaction = hex_transaction[328:]

        return Transaction(datetime.fromtimestamp(time_created), input_ids, output_amounts)

    @staticmethod
    def hexify(number, length):
        """
        calculates hexadecimal value of the number, with prefix zeroes to match length
        :param number: number to calculate hex value for, in base 10
        :type number: int
        :param length: requested length of hexadecimal value
        :type length: int
        :return: hexadecimal value of the number, with prefix zeroes
        :rtype: str
        :raise Exception: ValueError (message size is larger than length)
        """
        if not isinstance(number, int):
            raise TypeError("Transaction.hexify(number, length): expected number to be of type int")
        if not isinstance(length, int):
            raise TypeError("Transaction.hexify(number, length): expected length to be of type int")
        if number < 0:
            raise ValueError("Transaction.hexify(number, length): expected non-negative value for number, received {} "
                             "instead".format(number))
        if length < 0:
            raise ValueError("Transaction.hexify(number, length): expected non-negative value for length, received {} "
                             "instead".format(length))

        hex_base = hex(number)[2:]

        if len(hex_base) <= length:
            hex_base = (length - len(hex_base)) * "0" + hex_base
            return hex_base
        else:
            raise ValueError("Transaction.hexify(number, length): message size is larger than length")


def main():
    pass


if __name__ == '__main__':
    main()