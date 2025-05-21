from tkinter import *
from tkinter import messagebox
from Crypto.Cipher import AES
import base64

# Padding
def pad(s):
    return s + (16 - len(s) % 16) * ' '

# Encrypt function
def encrypt_msg():
    msg = input_text.get("1.0", "end-1c")
    key = key_entry.get()

    if not key:
        messagebox.showwarning("Missing Key", "You forgot the secret key! 🗝️")
        return

    try:
        key_bytes = key.ljust(16)[:16].encode()
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        encrypted = base64.b64encode(cipher.encrypt(pad(msg).encode())).decode()
        output_text.delete("1.0", END)
        output_text.insert(END, encrypted)
    except Exception as e:
        messagebox.showerror("Encryption Failed", str(e))

# Decrypt function
def decrypt_msg():
    encrypted_msg = input_text.get("1.0", "end-1c")
    key = key_entry.get()

    if not key:
        messagebox.showwarning("Missing Key", "You need a key to unlock this message! 🔐")
        return

    try:
        key_bytes = key.ljust(16)[:16].encode()
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        decrypted = cipher.decrypt(base64.b64decode(encrypted_msg)).decode().strip()
        output_text.delete("1.0", END)
        output_text.insert(END, decrypted)
    except Exception as e:
        messagebox.showerror("Decryption Failed", str(e))

# GUI Setup
app = Tk()
app.title("📜 SecureMessageCraft - Spy Edition")
app.geometry("540x600")
app.config(bg="#fef3dc")  # Parchment background

title_label = Label(app, text="🕵️‍♂️ Secret Message Encoder", font=("Georgia", 16, "bold"), bg="#fef3dc", fg="#5e3b1c")
title_label.pack(pady=10)

# Key input
Label(app, text="🔑 Enter Your Secret Key", font=("Georgia", 12, "bold"), bg="#fef3dc", fg="#5e3b1c").pack()
key_entry = Entry(app, width=40, show="*", font=("Courier New", 12), bg="#fffaf0", fg="#333")
key_entry.pack(pady=5)

# Input Message
Label(app, text="📝 Write Your Message Below", font=("Georgia", 12, "bold"), bg="#fef3dc", fg="#5e3b1c").pack(pady=5)
input_text = Text(app, height=6, width=60, font=("Courier New", 11), bg="#fffaf0")
input_text.pack(pady=5)

# Buttons
Button(app, text="🔒 Encrypt Message", command=encrypt_msg, bg="#8b4513", fg="white", font=("Georgia", 11), width=20).pack(pady=5)
Button(app, text="🔓 Decrypt Message", command=decrypt_msg, bg="#556b2f", fg="white", font=("Georgia", 11), width=20).pack(pady=5)

# Output
Label(app, text="📤 Encrypted / Decrypted Output", font=("Georgia", 12, "bold"), bg="#fef3dc", fg="#5e3b1c").pack(pady=5)
output_text = Text(app, height=6, width=60, font=("Courier New", 11), bg="#fffaf0")
output_text.pack(pady=5)

# Footer
Label(app, text="📦 Crafted by: MarkyPogi 🧶 | AES-128 ECB Mode", font=("Georgia", 9), bg="#fef3dc", fg="#7a4c26").pack(pady=10)

app.mainloop()
from tkinter import *
from tkinter import messagebox
from Crypto.Cipher import AES
import base64

# Padding
def pad(s):
    return s + (16 - len(s) % 16) * ' '

# Encrypt function
def encrypt_msg():
    msg = input_text.get("1.0", "end-1c")
    key = key_entry.get()

    if not key:
        messagebox.showwarning("Missing Key", "You forgot the secret key! 🗝️")
        return

    try:
        key_bytes = key.ljust(16)[:16].encode()
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        encrypted = base64.b64encode(cipher.encrypt(pad(msg).encode())).decode()
        output_text.delete("1.0", END)
        output_text.insert(END, encrypted)
    except Exception as e:
        messagebox.showerror("Encryption Failed", str(e))

# Decrypt function
def decrypt_msg():
    encrypted_msg = input_text.get("1.0", "end-1c")
    key = key_entry.get()

    if not key:
        messagebox.showwarning("Missing Key", "You need a key to unlock this message! 🔐")
        return

    try:
        key_bytes = key.ljust(16)[:16].encode()
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        decrypted = cipher.decrypt(base64.b64decode(encrypted_msg)).decode().strip()
        output_text.delete("1.0", END)
        output_text.insert(END, decrypted)
    except Exception as e:
        messagebox.showerror("Decryption Failed", str(e))

# GUI Setup
app = Tk()
app.title("📜 SecureMessageCraft - Spy Edition")
app.geometry("540x600")
app.config(bg="#fef3dc")  # Parchment background

title_label = Label(app, text="🕵️‍♂️ Secret Message Encoder", font=("Georgia", 16, "bold"), bg="#fef3dc", fg="#5e3b1c")
title_label.pack(pady=10)

# Key input
Label(app, text="🔑 Enter Your Secret Key", font=("Georgia", 12, "bold"), bg="#fef3dc", fg="#5e3b1c").pack()
key_entry = Entry(app, width=40, show="*", font=("Courier New", 12), bg="#fffaf0", fg="#333")
key_entry.pack(pady=5)

# Input Message
Label(app, text="📝 Write Your Message Below", font=("Georgia", 12, "bold"), bg="#fef3dc", fg="#5e3b1c").pack(pady=5)
input_text = Text(app, height=6, width=60, font=("Courier New", 11), bg="#fffaf0")
input_text.pack(pady=5)

# Buttons
Button(app, text="🔒 Encrypt Message", command=encrypt_msg, bg="#8b4513", fg="white", font=("Georgia", 11), width=20).pack(pady=5)
Button(app, text="🔓 Decrypt Message", command=decrypt_msg, bg="#556b2f", fg="white", font=("Georgia", 11), width=20).pack(pady=5)

# Output
Label(app, text="📤 Encrypted / Decrypted Output", font=("Georgia", 12, "bold"), bg="#fef3dc", fg="#5e3b1c").pack(pady=5)
output_text = Text(app, height=6, width=60, font=("Courier New", 11), bg="#fffaf0")
output_text.pack(pady=5)

# Footer
Label(app, text="📦 Crafted by: You 🧶 | AES-128 ECB Mode", font=("Georgia", 9), bg="#fef3dc", fg="#7a4c26").pack(pady=10)

app.mainloop()
