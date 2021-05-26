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

        self.config_button = Button(self.b_frame, width=10, font=("Times New Roman", 12), text="Configure\n⚙",
                                    command=self.configure_command)
        self.refresh_button = Button(self.b_frame, width=10, font=("Times New Roman", 12), text="Refresh\n⟳", command=self.refresh_command)
        self.pay_button = Button(self.b_frame, width=10, font=("Times New Roman", 12), text="Pay\n💳", command=self.pay_command)

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
            "public key": str,
            "private key": str
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

        except (ConnectionError, ConnectionResetError, ConnectionRefusedError, OSError) as e:
            messagebox.showerror(title="Connection Error",
                                 message="Failed to connect to wallet server.\nPlease try again by refreshing.\nError: {}".format(
                                     e))
        else:
            try:
                sock.send(self.build_wallet_request_message(self.config("public key")))
            except (
            ConnectionError, ConnectionResetError, ConnectionRefusedError, ConnectionAbortedError, OSError) as e:
                messagebox.showerror(title="Connection Error",
                                     message="Failed to send request to wallet server.\nPlease try again by refreshing.\n Error: {}".format(
                                         e))
            else:
                size_length = 5
                try:
                    size = sock.recv(size_length).decode()

                    while size.replace('f', '') == '':
                        size_length *= 2
                        size = sock.recv(size_length).decode()
                except (
                ConnectionError, ConnectionResetError, ConnectionRefusedError, ConnectionAbortedError, OSError) as e:
                    messagebox.showerror(title="Connection Error",
                                         message="Failed to receive reply from wallet server.\nPlease try again by refreshing.\nError: {}".format(
                                             e))

                else:
                    size = int(size, 16)
                    try:
                        data = sock.recv(size)
                    except (ConnectionError, ConnectionResetError, ConnectionRefusedError, ConnectionAbortedError,
                            OSError) as e:
                        messagebox.showerror(title="Connection Error",
                                             message="Failed to receive reply from wallet server.\nPlease try again by refreshing.\nError: {}".format(
                                                 e))
                    else:

                        self.title_text.set(data[1:9])

                        data = data[9:]

                        t_count = data[:6]
                        data = data[6:]
                        self.transactions = []
                        for x in range(int(t_count, 16)):
                            transaction_size = data[:5]

                            transaction = Transaction.from_network_format(data[5:5 + transaction_size])
                            self.transactions.append(transaction)

                            data = data[5 + transaction_size:]

                        if not len(self.transactions):
                            self.t_data.insert(END, "")
                            self.next_button["state"] = "disabled"
                            self.prev_button["state"] = "disabled"
                        else:
                            self.index = 0
                            self.t_data["state"] = "normal"
                            self.t_data.delete(1.0, END)
                            self.t_data.insert(END, str(self.transactions[self.index]))
                            self.t_data["state"] = "disabled"

                            self.prev_button["state"] = "disabled"

                            if len(self.transactions) > 1:
                                self.next_button["state"] = "normal"
                            else:
                                self.next_button["state"] = "disabled"

                        sock.close()

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
                sock.connect((self.config("server ip address"), self.config("server port")))\

            except (OSError, ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError, ConnectionError) as e:
                messagebox.showerror(title="Connection Error", message="Failed to connect to server.\nPlease try again.\nError: {}".format(e))

            else:
                try:
                    sock.send(msg.encode())
                except (OSError, ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError, ConnectionError) as e:
                    messagebox.showerror(title="Connection Error", message="Failed to send payment message to server.\nPlease try again.\nError: {}".format(e))
                else:
                    messagebox.showinfo(message="Sent Transaction!\nTransaction is now pending @ wallet server.")

                    try:
                        size = sock.recv(5)
                    except (OSError, ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError, ConnectionError) as e:
                        messagebox.showerror(title="Connection Error", message="Failed to receive reply to server.\nError: {}".format(e))
                    else:
                        try:
                            data = sock.recv(int(size, 16))
                        except (OSError, ConnectionAbortedError, ConnectionRefusedError, ConnectionResetError, ConnectionError) as e:
                            messagebox.showerror(title="Connection Error", message="Failed to receive reply to server.\nError: {}".format(e))
                        else:
                            sock.close()
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
    def build_wallet_request_message(src_key):
        return "00145i{}".format(src_key)

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
        pass

    pass


def main():
    window = WalletWindow()
    window.mainloop()
    pass


if __name__ == '__main__':
    main()
