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
from tkinter import messagebox

process = ""


def config(labels, entries, types):
    for i, key in enumerate(labels):
        entry = entries[i][1]
        value = entry.get()
        try:
            types[key](value)
        except ValueError:
            pass
        else:
            labels[key] = types[key](value)

    with open("Dependencies\\config.cfg", "wb") as file:
        pickle.dump(labels, file)
    var = tk.StringVar()
    var.set("Configured")
    msg = messagebox.showinfo(title="Configured", message="Configured!")

    terminate_full_node()


def run_full_node():
    global process
    if not isinstance(process, subprocess.Popen):
        logging.info("Initiating process...")
        process = subprocess.Popen(['python', 'Dependencies\\__main__.py'])
    else:
        logging.info("Process already initiated...")


def terminate_full_node():
    global process
    if isinstance(process, subprocess.Popen):
        logging.info("Terminating process...")
        process.kill()
        process = ""
    else:
        logging.info("Process already terminated...")
    pass


def on_closing():
    """
    :return:
    :rtype:
    """
    terminate_full_node()
    exit()


def main():
    window = tk.Tk()
    window.title("Full Node")
    window.resizable(width=False, height=False)
    window.protocol("WM_DELETE_WINDOW", on_closing)
    with open("Dependencies\\config.cfg", "rb") as infile:
        values: dict = pickle.load(infile)

    types = {
        "ip address": str,
        "port": int,
        "seed address": str,
        "seed port": int,
        "sql address": str,
        "sql user": str,
        "sql password": str,
        "default difficulty": int,
        "block reward": int,
        "difficulty change count": int,
        "public key": str
    }

    entries = []
    for key in values:
        var = tk.StringVar()
        var.set(values[key])
        entry = tk.Entry(width=30, textvariable=var)
        entry.bind("<Button-1>")
        label = tk.Label(text=key, justify=tk.LEFT, anchor="w")
        entries.append((label, entry))

    for i, entry in enumerate(entries):
        entry[0].grid(sticky=tk.W, column=0, row=i)
        entry[1].grid(column=1, row=i)

    run_button = tk.Button(window, width=10, text="configure", command=lambda: config(values, entries, types))
    run_button.grid(row=len(values), column=0)

    terminate_button = tk.Button(window, width=10, text="terminate", command=lambda: terminate_full_node())
    terminate_button.grid(row=len(values) + 2, column=1)

    space_frame = tk.Frame(window, width=10, height=10)
    space_frame.grid(row=len(values) + 1, column=0)

    run_button = tk.Button(window, width=10, text="run", command=lambda: run_full_node())
    run_button.grid(row=len(values) + 2, column=0)

    tk.mainloop()
    pass


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format="%(threadName)s [%(asctime)s]: %(message)s")
    main()
