import os
import zipfile
import os
import sys
import time
import random
import struct
import getpass
import re
from Crypto.Cipher import Blowfish
from Crypto import Random
import zipfile
import shutil
import pyAesCrypt
from tkinter import *
import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
import hashlib
import tkinter.simpledialog

root = tk.Tk()  # creating a dialog root window
root.title('Group 23 Encryption App')
root.geometry("600x500")

rdoBtn = tk.IntVar()


bufferSize = 64 * 1024

filename = ""  # initializing variable for file name to be used for blowfish algorithm


def encrypt_blow():
    filename = filedialog.askopenfilename(
        initialdir="/", title="Select file", filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
    if not filename:
        return  # Return if no file is selected
    # will show dialog box asking for password
    key = tkinter.simpledialog.askstring(
        "Password", "Enter password to use for your encryption", show='*')
    if not key:
        return  # Return if no password is entered
    # password converted using the hashlibrary
    password_bytes = key.encode('utf-8')
    hashed_pass = hashlib.sha256(password_bytes).hexdigest()
    chunksize = 64 * 1024
    # spaces or characters removed
    output_filename = re.sub(r'[<>:"/\\|?*]', "", os.path.basename(filename))
    directory = os.path.dirname(filename)
    output_file_path = os.path.join(directory, "(encrypted)" + output_filename)
    filesize = str(os.path.getsize(filename)).zfill(16)
    key_bytes = bytes.fromhex(hashed_pass)
    IV = Random.new().read(Blowfish.block_size)

    encryptor = Blowfish.new(key_bytes, Blowfish.MODE_CBC, IV)

    with open(filename, 'rb') as infile:
        with open(output_file_path, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))


def decrypt_blow():
    filename = filedialog.askopenfilename(
        initialdir="/", title="Select file", filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
    if not filename:
        return  # Return if no file is selected

    key = tkinter.simpledialog.askstring(
        "Password", "Enter password to use for your encryption", show='*')
    if not key:
        return  # Return if no password is entered

    password_bytes = key.encode('utf-8')
    hashed_pass = hashlib.sha256(password_bytes).hexdigest()
    chunksize = 64 * 1024
    output_filename = re.sub(r'[<>:"/\\|?*]', "", os.path.basename(filename))
    directory = os.path.dirname(filename)
    output_file_path = os.path.join(directory, "(decrypted)" + output_filename)

    with open(filename, 'rb') as infile:
        filesize = int(infile.read(16))
        IV = infile.read(8)

        decryptor = Blowfish.new(bytes.fromhex(
            hashed_pass), Blowfish.MODE_CBC, IV)

        with open(output_file_path, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break

                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(filesize)

# Creating a file path selection dialog


def filepath():
    global filename
    filename = filedialog.askopenfilename(
        initialdir="/", title="Select file",
        filetypes=(("Text files", "*.txt"), ("zip files", "*.zip"),
                   ("image files", "*.png *.jpg *.jpeg *.svg *.webp *.avif *.apng *.gif *.pjpeg *.pjp *.jfif"),
                   ("powerpoint files", "*.pptx *.ppt *.pptm"), ("All files", "*.*")))
    print(filename)
    my_FileText.insert(END, filename)
    if not filename:
        # Return if no file is selected
        return messagebox.showinfo("Select File", "No file selected.")


def own_algoEnc():
    # own algorithm for encrypting
    # putting password entered by the user in a variable
    password = tkinter.simpledialog.askstring(
        "Password", "Enter password to use for your encryption", show='*')

    # converting password into bytes as hashlib requires bytes as input
    password_bytes = password.encode('utf-8')

    # will generate a SHA-256 hash of the password
    hashed_pass = hashlib.sha256(password_bytes).hexdigest()
    # root.destroy() #will remove window
    if myEntry.get() == password:
        messagebox.showinfo(
            "Encryption Successful", "Encryption Successful")
        pyAesCrypt.encryptFile(
            filename, filename+".aes", password, bufferSize) #adds password in encrypted file, so you can decrypt from file found in file manager and not from app only 
        os.remove(filename) #removes the file after encrypting
        my_Text.insert(END, "DONE Encrypting\n")
        myEntry.delete(0, END) 
    else:
        messagebox.showinfo("Password", "no password entered")


def own_algoDec():
    # own algorithm for decrypting
    # putting password entered by the user in a variable
    password = tkinter.simpledialog.askstring(
        "Password", "Enter password to use for your encryption", show='*')

    # converting password into bytes as hashlib requires bytes as input
    password_bytes = password.encode('utf-8')

    # will generate a SHA-365 hash of the password
    hashed_pass = hashlib.sha256(password_bytes).hexdigest()

    if myEntry.get() == password:
        messagebox.showinfo(
            "Decryption Sucess", "Decryption Successful.")
        pyAesCrypt.decryptFile(
            filename, filename+".aes", password, bufferSize) 
        pyAesCrypt.decryptFile(
            filename, filename[:-4], password, bufferSize)
        os.remove(filename)
        os.remove(filename+".aes") # removes encrypted file after decrypting
        my_Text.insert(END, "DONE Decrypting")
        myEntry.delete(0, END)
    else:
        messagebox.showinfo("Password", "no password entered")


Label(root, text="\n\nChoose an algorithm", font='Arial 10 bold').pack()
tk.Radiobutton(root, text="Blowfish algorithm",
               variable=rdoBtn, value=1).pack()

tk.Radiobutton(root, text="Own algorithm",
               variable=rdoBtn, value=2).pack()


def close_window():
    root.destroy()


def encrypt():

    if rdoBtn.get() == 1:
        {  # calling Blowfish algorithm for encryption
            encrypt_blow(),
           my_Text.insert(END, "\nFile Encrypted")
        }
    elif rdoBtn.get() == 2:
        {
            # calling function for my own algorithm for decrypting files
            own_algoEnc()

        }
    else:
        {
            messagebox.showinfo("Select Algorithm",
                                "No selected algorithm for encrypting")

        }


def decrypt():

    if rdoBtn.get() == 1:
        {
            # calling Blowfish algorithm for decrypting
            decrypt_blow(),
            my_Text.insert(END, "\nFile Decrypted")
        }
    elif rdoBtn.get() == 2:
        {  # calling function for my own algorithm for decrypting files
            own_algoDec()

        }
    else:
        {
            messagebox.showinfo("Select Algorithm",
                                "No selected algorithm for decrypting")
        }


# Creating a label for password prompt and adding it to the GUI
password_Label = Label(
    root, text="\n\nEnter your password below in order to encrypt or decrypt:",
    font=("Helvetica 10 bold"))
password_Label.pack()

#  Creating a text field for password
myEntry = Entry(root, font=('Helvetica'), width=25, show="*")
myEntry.pack()

# Creating spcae between objects in the GUI
myFrame = Frame(root)
myFrame.pack(pady=15)

# Creating a label for the file path
Label(root, text="File path:",
      font='Helvetica 10 bold').pack(pady=15)

# A textfield to display the file path
my_FileText = Text(root, font=("Helvatica ", 9), width=40, height=0.5)
my_FileText.pack()

# Browser button to open file directory
brwsButton = Button(myFrame, text="Browser File", font=(
    "Helvetica", 10), command=filepath)
brwsButton.grid(row=1, column=0)

# Creating space between objects in the GUI
myFrame = Frame(root)
myFrame.pack(pady=10)

# Initializing encryption and decryption buttons
encButton = Button(myFrame, text="Encrypt", font=(
    "Helvetica", 10), command=encrypt)
encButton.grid(row=1, column=1, padx=10)

decButton = Button(myFrame, text="Decrypt", font=(
    "Helvetica", 10), command=decrypt)
decButton.grid(row=1, column=2, padx=20)

# Create a prompt label for encryption process feedback
Label(root, text="File will show if encrypted or decrypted below",
      font='Arial 10 bold').pack(pady=15)

# A text field to display the feedback
my_Text = Text(root, width=20, height=0.5)
my_Text.pack(pady=10)

# Creating a space between objects in the GUI
myFrame = Frame(root)
myFrame.pack(pady=1)

# Initializng a closing button to terminate the application
closeButton = Button(myFrame, text="Close", font=(
    "Helvetica", 10), command=close_window)
closeButton.grid(row=1, column=2)

root.mainloop()
