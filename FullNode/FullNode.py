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


def run():
    global process
    if not isinstance(process, subprocess.Popen):
        logging.info("Launching full node. . .")
        process = subprocess.Popen(['python', 'Dependencies\\__main__.py'])
    else:
        logging.info("Process already initiated. . .")


def terminate(silent=False):
    global process
    if isinstance(process, subprocess.Popen):
        if not silent:
            logging.info("Terminating process. . . ")
        process.kill()
        process = ""
    else:
        if not silent:
            logging.info("Process already terminated. . .")


def config():
    config_window = tk.Tk()
    config_window.title("")
    config_window.iconbitmap("Dependencies\\configure.ico")
    config_window.resizable(width=False, height=False)

    with open("Dependencies\\config.cfg", "rb") as infile:
        values = pickle.load(infile)

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
        frame = tk.Frame(config_window)
        entry = tk.Entry(frame, width=30 , justify=tk.LEFT)
        entry.insert(tk.END, values[key])
        label = tk.Label(frame, text=key, justify=tk.LEFT, anchor="e")

        label.pack(side=tk.TOP)
        entry.pack(side=tk.TOP)
        frame.pack(side=tk.TOP)
        entries.append((label, entry))

    run_button = tk.Button(config_window, width=10, text="⚙", command=lambda: configure(values, entries, types, config_window))
    run_button.pack(side=tk.TOP)
    # run_button.grid(row=len(values), column=0)

    config_window.mainloop()


def configure(labels, entries, types, window):
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
    terminate(silent=True)



def on_closing():
    """
    :return:
    :rtype:
    """
    terminate(silent=True)
    exit()


def main():
    myFont = ("Times New Roman", 20, "bold")
    window = tk.Tk()
    window.title("SittCoin")
    window.wm_iconbitmap('Dependencies\\miner.ico')
    window.resizable(width=False, height=False)
    window.protocol("WM_DELETE_WINDOW", on_closing)

    title = tk.Label(window, width=35, text="SittCoin Full Node")
    title.pack(side=tk.TOP)

    spacer = tk.Frame(window, width=1, height=10)
    spacer.pack(side=tk.TOP)

    run_button = tk.Button(window, width=3, text="▶", font=myFont, command=lambda: run())
    run_button.pack(side=tk.LEFT)

    configure_button = tk.Button(window, width=3, text="⚙", command=lambda: config())
    configure_button['font'] = myFont
    configure_button.pack(side=tk.RIGHT)

    terminate_button = tk.Button(window, width=3, text="■", command=lambda: terminate())
    terminate_button['font'] = myFont
    terminate_button.pack(side=tk.TOP)
    window.mainloop()

    pass


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format="%(threadName)s [%(asctime)s]: %(message)s")
    main()
# TODO: public key field as directory, not string
