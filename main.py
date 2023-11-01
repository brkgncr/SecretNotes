import tkinter
from tkinter import *
from tkinter import messagebox
from PIL import Image, ImageTk

import base64


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def save_and_encrypt_notes():
    title = my_title_entry.get()
    message = my_note_text.get("1.0", END)
    master_secret = my_key_entry.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0:
        messagebox.showerror(title="Error", message="Please enter all info.")
    else:
        # encryption
        message_encrypted = encode(master_secret, message)
        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        finally:
            my_title_entry.delete(0, END)
            my_note_text.delete("1.0", END)
            my_key_entry.delete(0, END)


def decrypt_notes():
    message_encrypted = my_note_text.get("1.0", END)
    master_secret = my_key_entry.get()

    if len(message_encrypted) == 0 or len(master_secret) == 0:
        messagebox.showinfo(title="Error", message="Please enter all info.")
    else:
        try:
            decrypt_message = decode(master_secret, message_encrypted)
            my_note_text.delete("1.0", END)
            my_note_text.insert("1.0", decrypt_message)
        except:
            messagebox.showinfo(title="Error!", message="Please enter encrypted text!")


window = tkinter.Tk()
window.title("Secret Notes")
window.minsize(width=400, height=600)

image = Image.open("images.jpg")
photo = ImageTk.PhotoImage(image)
my_image = tkinter.Label(image=photo)
my_image.pack()

my_title_label = tkinter.Label(text="Entry your title", font=("Helvetica", 12, "bold"))
my_title_label.pack()

my_title_entry = tkinter.Entry(width=45)
my_title_entry.pack()

my_secret_label = tkinter.Label(text="Entry your secret", font=("Helvetica", 12, "bold"))
my_secret_label.pack()

my_note_text = tkinter.Text(width=38, height=13)
my_note_text.pack()

my_master_label = tkinter.Label(text="Entry master key", font=("Helvetica", 12, "bold"))
my_master_label.pack()

my_key_entry = tkinter.Entry(width=45)
my_key_entry.pack()

my_save_button = tkinter.Button(text="Save & Encrypt", command=save_and_encrypt_notes)
my_save_button.pack()

my_dec_button = tkinter.Button(text="Decrypt", command=decrypt_notes)
my_dec_button.pack()

window.mainloop()
