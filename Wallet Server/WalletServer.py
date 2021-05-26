"""
Author: Oren Sitton
File: FullNode.py
Python Version: 3
Description: Configure & run full node.
"""
import logging
import pickle
import subprocess
import tkinter as tk
from tkinter import *
from tkinter import messagebox


class FullNodeWindow(Tk):
    def __init__(self):
        super().__init__()

        self.state = False
        self.process = ""
        self.title("SittCoin Wallet Server")
        self.iconbitmap("Dependencies\\GUI\\wallet.ico")
        self.resizable(width=False, height=False)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.title = Label(self, width=20, text="SittCoin Wallet Server", font=("Palatino", 20))

        self.run_button = Button(self, width=10, text="Run\n▶", font=("Times New Roman", 12), command=self.run_command)
        self.terminate_button = Button(self, width=10, text="Terminate\n■", font=("Times New Roman", 12), command=self.terminate_command)
        self.configure_button = Button(self, width=10, text="Configure\n⚙", font=("Times New Roman", 12), command=self.configure_command)

        self.terminate_button["state"] = "disabled"

        self.title.pack(side=TOP)

        self.run_button.pack(side=LEFT, padx=5, pady=20)
        self.terminate_button.pack(side=LEFT, padx=5, pady=20)
        self.configure_button.pack(side=LEFT, padx=5, pady=20)

    def terminate_command(self):
        if not self.state:
            return
        logging.info("Terminating full node process. . . . .")
        self.process.kill()

        self.state = False
        self.terminate_button["state"] = "disabled"
        self.run_button["state"] = "normal"

    def run_command(self):
        if self.state:
            return

        logging.info("Launching full node process. . . . .")
        self.process = subprocess.Popen(["python", "Dependencies\\__main__.py"])
        self.state = True

        self.run_button["state"] = "disabled"
        self.terminate_button["state"] = "normal"

    def configure_command(self):
        config_window = Tk()
        config_window.title("")
        config_window.iconbitmap("Dependencies\\GUI\\configure.ico")
        config_window.resizable(width=False, height=False)

        with open("Dependencies\\config.cfg", "rb") as infile:
            values= pickle.load(infile)

        types = {
            "node ip address": str,
            "node port": int,
            "wallet ip address": str,
            "wallet port": int,
            "seed address": str,
            "seed port": int,
            "sql address": str,
            "sql user": str,
            "sql password": str,
            "default difficulty": int,
            "block reward": int,
            "difficulty change count": int,
        }

        entries = []
        for key in values:
            frame = tk.Frame(config_window)
            entry = tk.Entry(frame, width=30, justify=tk.LEFT)
            entry.insert(tk.END, values[key])
            label = tk.Label(frame, text=key, justify=tk.LEFT, anchor="e")

            label.pack(side=tk.TOP)
            entry.pack(side=tk.TOP)
            frame.pack(side=tk.TOP)
            entries.append((label, entry))

        run_button = tk.Button(config_window, width=10, text="⚙",
                               command=lambda: self.config(values, entries, types, config_window))
        run_button.pack(side=tk.TOP)

        config_window.mainloop()

    def config(self, labels, entries, types, window):
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
        self.terminate_command()

    def on_closing(self):
        self.terminate_command()
        exit(-1)
        pass


def main():
    window = FullNodeWindow()
    window.mainloop()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format="%(threadName)s [%(asctime)s]: %(message)s")
    main()
