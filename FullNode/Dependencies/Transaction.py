"""
Author: Oren Sitton
File: Transaction.py
Python Version: 3
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
    inputs : list[(public key, block number, transaction number, signature)]
        list of transaction sources & signatures
    outputs : list[(public key, amount)]
        list of transaction output amounts & destinations

    Methods
    -------
    __init__(timestamp, inputs, outputs)
        initializes transaction instance
    __str__()
        returns string format of transaction
    network_format()
        converts Transaction object into a hexadecimal string of the transaction in the network protocol format
    signing_format()
        converts Transaction object into a hexadecimal string of the transaction as per signing protocol
    sha256_hash()
        calculates sha256 hash of the transaction, per the Blemflark protocol

    Static Methods
    --------------
    from_network_format(hex_transaction)
        creates a Transaction object from a string, containing a transaction in the network protocol format
    hexify(number, length)
        calculates hexadecimal value of the number, with prefix zeroes to match length
    """
    def __init__(self, timestamp, inputs, outputs):
        """
        initiates transaction object
        :param timestamp: time of the transaction
        :type timestamp: datetime/int
        :param inputs: list of input keys, input sources & signatures, as tuples (input address, transaction block
                       number, transaction number, sender's signature)
        :type inputs: list
        :param outputs: list of output keys & amount per key, as tuples (output key, amount)
        :type outputs: list
        """
        if not (isinstance(timestamp, int) or isinstance(timestamp, datetime)):
            raise TypeError("Transaction.__init__: expected timestamp to be of type int "
                            "or datetime")
        for inp in inputs:
            if len(inp) != 4:
                raise ValueError("Transaction.__init__: expected input tuples to be of a length of 4")
        for out in outputs:
            if len(out) != 2:
                raise ValueError("Transaction.__init__: expected output tuples to be of a length of 2")

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
            string_representation += "{}: {}.{}  |  {}\n".format(inp[0], inp[1], inp[2], inp[3])
        string_representation += "Outputs:\n"
        for output in self.outputs:
            string_representation += "{}: {}Bl\n".format(output[0], output[1])
        return string_representation[:-1]
      
    def __gt__(self, other):
        if int(self.inputs[0], 16) < int(other.inputs[0], 16):
            return False
        elif self.inputs[1] < other.inputs[1]:
            return False
        elif self.inputs[2] < other.inputs[2]:
            return False
        return True

    def __lt__(self, other):
        if int(self.inputs[0], 16) > int(other.inputs[0], 16):
            return False
        elif self.inputs[1] > other.inputs[1]:
            return False
        elif self.inputs[2] > other.inputs[2]:
            return False
        return True

    def overlap(self, other):
        for inp in self.inputs:
            for other_inp in other.inputs:
                if inp[0] == other_inp[0] and inp[1] == other_inp[1] and inp[2] == other_inp[2]:
                    return True
        return False

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

        message = "e{}{}{}".format(time_created, inputs_amount, outputs_amount)

        for inp in self.inputs:
            input_key = inp[0]
            input_block_number = Transaction.hexify(inp[1], 6)
            input_transaction_number = Transaction.hexify(inp[2], 2)
            signature = inp[3]

            message += input_key + input_block_number + input_transaction_number + signature

        for output in self.outputs:
            output_address = output[0]
            amount = Transaction.hexify(output[1], 4)

            message += output_address + amount
        message = message.replace(" ", "")
        return message

    def signing_format(self):
        """
        converts Transaction object into a hexadecimal string, as per signing protocol
        :return: hexadecimal transaction in signing format
        :rtype: str
        """
        inputs_amount = len(self.inputs)
        outputs_amount = len(self.outputs)

        message = "{}{}".format(inputs_amount, outputs_amount)

        for inp in self.inputs:
            input_key = inp[0]
            input_block_number = Transaction.hexify(inp[1], 6)
            input_transaction_number = Transaction.hexify(inp[2], 2)
            message += input_key + input_block_number + input_transaction_number
        for output in self.outputs:
            output_address = output[0]
            amount = Transaction.hexify(output[1], 4)
            message += output_address + amount
        return message

    def sha256_hash(self):
        """
        calculates sha256 hash of the transaction, per the Blemflark protocol
        :return: sha256 hash of the transaction, as a hexadecimal string
        :rtype: str
        """
        return sha256(self.network_format().encode()).hexdigest()

    @staticmethod
    def from_network_format(hex_transaction):
        """
        creates a Transaction object from a string, containing a transaction in the network protocol format
        :param hex_transaction: transaction in network protocol format
        :type hex_transaction: str
        :return: Transaction object
        :rtype: Transaction
        """
        if len(hex_transaction) < 11 or hex_transaction[0] != 'e':
            raise ValueError("Transaction.from_network_format(hex_transaction): hexadecimal value does not represent "
                             "valid transaction")

        hex_transaction = hex_transaction[1:]
        time_created = int(hex_transaction[0:8], 16)
        amount_of_inputs = int(hex_transaction[8:9], 16)
        amount_of_outputs = int(hex_transaction[9:10], 16)

        if len(hex_transaction) != 10 + amount_of_inputs * 588 + amount_of_outputs * 328:
            raise ValueError("Transaction.from_network_format(hex_transaction): hexadecimal value does not represent "
                             "valid transaction")

        hex_transaction = hex_transaction[10:]

        inputs = []
        outputs = []

        for i in range(amount_of_inputs):
            input_key = hex_transaction[0:324]
            input_block_number = int(hex_transaction[324:330], 16)
            input_transaction_number = int(hex_transaction[330:332], 16)
            signature = hex_transaction[332: 588]

            inputs.append((input_key, input_block_number, input_transaction_number, signature))
            hex_transaction = hex_transaction[588:]

        for i in range(amount_of_outputs):
            output_address = hex_transaction[0:324]
            output_amount = int(hex_transaction[324: 328], 16)

            outputs.append((output_address, output_amount))
            hex_transaction = hex_transaction[328:]

        return Transaction(datetime.fromtimestamp(time_created), inputs, outputs)

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
