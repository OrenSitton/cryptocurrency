"""
Author: Oren Sitton
File: BlockViewer.py
Python Version: 3
Description: 
"""
from tkinter.scrolledtext import *
from tkinter import *
from Dependencies import Block
from Dependencies import Blockchain


class WalletWindow(Tk):
    def __init__(self):
        super().__init__()
        super().title("SittCoin Wallet")
        super().resizable(width=False, height=False)
        super().protocol("WM_DELETE_WINDOW", self.on_closing)

        self.index = 1

        # title
        self.title_text = StringVar()
        self.title_text.set("Block number: {}".format("N/A"))
        self.title = Label(self, width=25, textvariable=self.title_text, font=("Times New Roman", 25))

        # transaction data
        self.t_frame = Frame(self)

        self.prev_button = Button(self.t_frame, text="<", font=("Times New Roman", 30), width=1,
                                  command=self.prev_command)
        self.next_button = Button(self.t_frame, text=">", font=("Times New Roman", 30), width=1,
                                  command=self.next_command)

        self.t_data = ScrolledText(self.t_frame, wrap=WORD, width=150, height=30, font=("Times New Roman", 15))
        self.t_data.configure(state="disabled")
        self.t_data.focus()

        # buttons
        self.b_frame = Frame(self)

        # packing
        self.title.pack(side=TOP)

        self.prev_button.pack(side=LEFT, padx=5)
        self.t_data.pack(side=LEFT)
        self.next_button.pack(side=LEFT, padx=5)
        self.t_frame.pack(side=TOP)

        self.prev_button["state"] = "disable"
        self.next_button["state"] = "disable"

        self.blockchain = Blockchain()
        if len(self.blockchain) == 0:
            pass
        elif len(self.blockchain) == 1:
            self.t_data.configure(state="normal")
            self.t_data.insert(END, str(self.blockchain.get_block_consensus_chain(1)))
            self.title_text.set("Block number: {}".format(1))
            self.t_data.configure(state="disabled")
        else:
            self.t_data.configure(state="normal")
            self.t_data.insert(END, str(self.blockchain.get_block_consensus_chain(1)))
            self.title_text.set("Block number: {}".format(1))
            self.t_data.configure(state="disabled")
            self.next_button["state"] = "normal"


    def next_command(self):
        self.index += 1
        self.t_data.configure(state="normal")
        self.t_data.delete(1.0, END)
        self.t_data.insert(END, str(self.blockchain.get_block_consensus_chain(self.index)))
        self.title_text.set("Block number: {}".format(self.index))
        self.t_data.configure(state="disabled")
        if self.index == len(self.blockchain):
            self.next_button["state"] = "disabled"
        self.prev_button["state"] = "normal"

    def prev_command(self):
        self.index -= 1
        self.t_data.configure(state="normal")
        self.t_data.delete(1.0, END)
        self.t_data.insert(END, str(self.blockchain.get_block_consensus_chain(self.index)))
        self.title_text.set("Block number: {}".format(self.index))
        self.t_data.configure(state="disabled")
        if self.index == 1:
            self.prev_button["state"] = "disabled"
        self.next_button["state"] = "normal"


    def on_closing(self):
        exit(1)



def main():
    WalletWindow().mainloop()
    pass


if __name__ == '__main__':
    main()
