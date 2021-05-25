"""
Author: Oren Sitton
File: Wallet.py
Python Version: 3
Description: 
"""
import pickle
import socket
from tkinter import Entry
from tkinter import *
from tkinter import messagebox
from tkinter.scrolledtext import *

from Dependencies.Transaction import Transaction


class WalletWindow(Tk):
    def __init__(self):
        super().__init__()
        super().title("SittCoin Wallet")
        super().iconbitmap("Dependencies\\wallet.ico")
        super().resizable(width=False, height=False)
        super().protocol("WM_DELETE_WINDOW", self.on_closing)

        self.transactions = ["1", "2", "3", "4", "5"]
        self.wallet_amount = 999999999
        self.index = 0

        # title
        self.title_text = StringVar()
        self.title_text.set("{:,} SittCoin".format(self.wallet_amount))
        self.title = Label(self, width=25, textvariable=self.title_text, font=("Times New Roman", 25))

        # transaction data
        self.t_frame = Frame(self)

        self.prev_button = Button(self.t_frame, text="<", font=("Times New Roman", 30), width=1,
                                  command=self.prev_command)
        self.next_button = Button(self.t_frame, text=">", font=("Times New Roman", 30), width=1,
                                  command=self.next_command)

        self.t_data = ScrolledText(self.t_frame, wrap=WORD, width=40, height=10, font=("Times New Roman", 15))
        self.t_data.configure(state="disabled")
        self.t_data.focus()

        # buttons
        self.b_frame = Frame(self)

        self.config_button = Button(self.b_frame, font=("Times New Roman", 30), text="⚙", command=self.configure_command)
        self.refresh_button = Button(self.b_frame, font=("Times New Roman", 30), text="⟳", command=self.refresh_command)
        self.pay_button = Button(self.b_frame, font=("Times New Roman", 30), text="💳", command=self.pay_command)

        # packing
        self.title.pack(side=TOP)

        self.prev_button.pack(side=LEFT, padx=5)
        self.t_data.pack(side=LEFT)
        self.next_button.pack(side=LEFT, padx=5)
        self.t_frame.pack(side=TOP)

        self.config_button.pack(side=LEFT, padx=30, pady=20)
        self.refresh_button.pack(side=LEFT, padx=30, pady=20)
        self.pay_button.pack(side=LEFT, padx=30, pady=20)
        self.b_frame.pack(side=TOP)

        self.prev_button["state"] = "disable"
        self.next_button["state"] = "disable"

        self.pay_window = 0

        self.refresh_command()

    def configure_command(self):
        config_window = Tk()
        config_window.title("")
        config_window.iconbitmap("Dependencies\\configure.ico")
        config_window.resizable(width=False, height=False)

        with open("Dependencies\\config.cfg", "rb") as infile:
            values = pickle.load(infile)

        types = {
            "server ip address": str,
            "server port": int,
            "public key location": str,
            "private key location": str
        }

        entries = []
        for key in values:
            frame = Frame(config_window)
            entry = Entry(frame, width=30, justify=LEFT)
            entry.insert(END, values[key])
            label = Label(frame, text=key, justify=LEFT, anchor="e")

            label.pack(side=TOP)
            entry.pack(side=TOP)
            frame.pack(side=TOP)
            entries.append((label, entry))

        configure_button = Button(config_window, width=10, text="⚙",
                                  command=lambda: self.config_data(values, entries, types, config_window))
        configure_button.pack(side=TOP)

        config_window.mainloop()

    @staticmethod
    def config_data(labels, entries, types, window):
        for i, key in enumerate(labels):
            entry = entries[i][1]
            value = entry.get()
            try:
                types[key](value)
            except ValueError:
                pass
            else:
                if value:
                    labels[key] = types[key](value)
        with open("Dependencies\\config.cfg", "wb") as file:
            pickle.dump(labels, file)
        window.destroy()
        messagebox.showinfo(title="Configured", message="Configured!")

    def refresh_command(self):
        sock = socket.socket()

        try:
            sock.connect((self.config("server ip address"), self.config("server port")))

            size_length = 5
            size = sock.recv(size_length).decode()

            while size.replace('f', '') == '':
                size_length *= 2
                size = sock.recv(size_length).decode()

            size = int(size, 16)

            data = sock.recv(size)

            self.title_text.set(data[1:9])

            data = data[9:]

            t_count = data[9:15]
            data = data[15:]
            self.transactions = []
            for x in range(int(t_count, 16)):
                transaction_size = data[:5]

                transaction = Transaction.from_network_format(data[5:5 + transaction_size])

            data = data[5 + transaction_size:]

        except (TimeoutError, ConnectionError, ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError):
            messagebox.showerror(title="Connection Error",
                                 message="Failed to connect to wallet server, please try again by refreshing. . .")
        except OSError:
            messagebox.showerror(title="OS Error", message="OS Error, please check wallet configuration")
        else:
            if not len(self.transactions):
                pass
            else:
                self.index = 0
                self.t_data["state"] = "normal"
                self.t_data.delete(1.0, END)
                self.t_data(END, str(self.transactions[self.index]))
                self.t_data["state"] = "disabled"

                self.prev_button["state"] = "disabled"

                if len(self.transactions) > 1:
                    self.next_button["state"] = "normal"
                else:
                    self.next_button["state"] = "disabled"

    def pay_command(self):
        self.pay_window = Tk()
        self.pay_window.iconbitmap("Dependencies\\wallet.ico")
        self.pay_window.title("")


        self.pay_window.protocol("WM_DELETE_WINDOW", self.pay_on_closing)

        destination_label = Label(self.pay_window, text="Destination Address (x16)")
        destination_entry = Entry(self.pay_window)

        amount_label = Label(self.pay_window, text="Amount")
        amount_entry = Entry(self.pay_window)

        pay_button = Button(self.pay_window, text="💳", command=lambda: self.process_payment(self.pay_window, destination_entry, amount_entry))

        destination_label.pack(side=TOP)
        destination_entry.pack(side=TOP)

        amount_label.pack(side=TOP)
        amount_entry.pack(side=TOP)

        pay_button.pack(side=TOP)

        self.pay_window.mainloop()
        pass

    def process_payment(self, window, destination_entry, amount_entry):
        """

        :param destination_entry:
        :type destination_entry: Entry
        :param amount_entry:
        :type amount_entry: Entry
        :return:
        :rtype:
        """

        destination_address = destination_entry.get()
        amount = amount_entry.get()
        try:
            int(destination_address, 16)
        except ValueError:
            messagebox.showerror(title="Input Error", message="Destination address should be in hexadecimal format")
            return

        if len(destination_address) != 324:
            messagebox.showerror(title="Input Error", message="Destination address must be of length 324")
            return

        try:
            amount = int(amount)
        except ValueError:
            messagebox.showerror(title="Input Error", message="Amount should be integer")
            return
        else:
            # send reqeust to server

            sock = socket.socket()
            msg = self.build_payment_message(self.config("public key"), destination_address, amount)
            try:
                sock.connect((self.config("server ip address"), self.config("server port")))
                sock.send(msg.encode())

                # handle data
            except (TimeoutError, ConnectionError, ConnectionResetError, ConnectionRefusedError, ConnectionAbortedError):
                messagebox.showerror(title="Connection Error", message="Error while sending transaction to server")

            else:
                messagebox.showinfo(message="Sent transaction!")
                try:
                    size = int(sock.recv(5).decode(), 16)

                    data = sock.recv(size)
                except (ConnectionError, ConnectionResetError, ConnectionRefusedError, ConnectionAbortedError):
                    messagebox.showerror(title="Connection Error", message="Error while receiving response from server")
                else:
                    messagebox.showinfo(title="Server Response", message=self.parse_server_response(data))
                    window.destroy()

    def next_command(self):
        self.index += 1
        self.t_data.configure(state="normal")
        self.t_data.delete(1.0, END)
        self.t_data.insert(END, str(self.transactions[self.index]))
        self.t_data.configure(state="disabled")
        if self.index == len(self.transactions) - 1:
            self.next_button["state"] = "disabled"
        self.prev_button["state"] = "normal"

    def prev_command(self):
        self.index -= 1
        self.t_data.configure(state="normal")
        self.t_data.delete(1.0, END)
        self.t_data.insert(END, str(self.transactions[self.index]))
        self.t_data.configure(state="disabled")
        if self.index == 0:
            self.prev_button["state"] = "disabled"
        self.next_button["state"] = "normal"

    def on_closing(self):
        if isinstance(self.pay_window, Tk):
            self.pay_window.destroy()
        exit(1)

    def pay_on_closing(self):
        self.pay_window.destroy()
        self.pay_window = 0

    @staticmethod
    def config(key, directory="Dependencies\\config.cfg"):
        """
        returns data from configuration file
        :param key: dictionary key to return value of
        :type key: str
        :param directory: directory of configuration file, default Dependencies\\config.cfg
        :type directory: str
        :return: value of dictionary for key
        :rtype: Any
        :raises: FileNotFoundError: configuration file not found at directory
        :raises: TypeError: unpickled object is not a dictionary
        """
        if not isinstance(key, str):
            raise TypeError("config: expected key to be of type str")
        if not isinstance(directory, str):
            raise TypeError("config: expected directory to be of type str")
        try:
            with open(directory, "rb") as file:
                configuration = pickle.load(file)
        except FileNotFoundError:
            raise FileNotFoundError("config: configuration file not found at {}".format(directory))
        else:
            if not isinstance(configuration, dict):
                raise TypeError("config: expected file to contain pickled dict")
            else:
                return configuration.get(key)

    @staticmethod
    def build_payment_message(src_key, dest_key, amount):
        """

        :param src_key:
        :type src_key:
        :param dest_key:
        :type dest_key:
        :param amount:
        :type amount:
        :return:
        :rtype: str
        """
        pass

    @staticmethod
    def parse_server_response(data):
        """

        :param data:
        :type data:
        :return:
        :rtype: str
        """

    pass


def on_closing():
    exit(-1)


def build_wallet_amount_message():
    msg = "i{}".format(config("public key"))
    return "00145{}".format(msg)


def load_wallet(window, amount_text, data_text):
    sock = socket.socket()

    try:
        sock.connect((config("server ip"), config("server port")))

        sock.send(build_wallet_amount_message().encode())

        size = int(sock.recv(5), 16)

        data = sock.recv(size).decode()

        amount = int(data, 16)
    except (ConnectionResetError, ConnectionRefusedError, ConnectionAbortedError, ConnectionError):
        tk.messagebox.showinfo(title="Error",
                               message="Error connecting to wallet server, please re-attempt by refreshing")

    amount_text.set("{} SittCoin".format(amount))


def main():
    window = WalletWindow()
    window.mainloop()
    pass


if __name__ == '__main__':
    main()
