"""
Author: Oren Sitton
File: FullNode.py
Python Version: 3
Description: 
"""
import logging
import pickle
import subprocess
import tkinter as tk
from tkinter import messagebox

process = ""


def config(labels, entries, types, window):
    for i, key in enumerate(labels):
        entry = entries[i][1]
        value = entry.get()
        try:
            types[key](value)
        except ValueError:
            pass
        else:
            labels[key] = types[key](value)

    with open("Dependencies\\config.txt", "wb") as file:
        pickle.dump(labels, file)
    var = tk.StringVar()
    var.set("Configured")
    msg = messagebox.showinfo(title="Configured", message="Configured!")

    if isinstance(process, subprocess.Popen):
        process.kill()


def run_full_node(window):
    global process
    process = subprocess.Popen(['python', 'full_node.py'])


def on_closing():
    """
    :return:
    :rtype:
    """
    if isinstance(process, subprocess.Popen):
        process.kill()
    exit()


def main():
    window = tk.Tk()
    window.title("Full Node")
    window.resizable(width=False, height=False)
    window.protocol("WM_DELETE_WINDOW", on_closing)
    with open("Dependencies\\config.txt", "rb") as infile:
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

    run_button = tk.Button(window, width=10, text="configure", command=lambda: config(values, entries, types, window))
    run_button.grid(row=len(values), column=0)

    run_button = tk.Button(window, width=10, text="run", command=lambda: run_full_node(window, ))
    run_button.grid(row=len(values), column=1)

    tk.mainloop()
    pass


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format="%(threadName)s [%(asctime)s]: %(message)s")
    main()
