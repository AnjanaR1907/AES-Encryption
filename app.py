from tkinter import *
from tkinter import messagebox, scrolledtext
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def encrypt():
    try:
        key = key_entry.get().encode()
        key_size = int(key_size_var.get())
        plaintext = plaintext_text.get("1.0", END).strip().encode()

        if len(key) != key_size:
            messagebox.showerror("Error", f"Key must be {key_size} bytes long")
            return

        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
        ct = base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')
        ciphertext_text.delete("1.0", END)
        ciphertext_text.insert(END, ct)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt():
    try:
        key = key_entry.get().encode()
        key_size = int(key_size_var.get())
        ct = ciphertext_text.get("1.0", END).strip()
        ct_bytes = base64.b64decode(ct)

        if len(key) != key_size:
            messagebox.showerror("Error", f"Key must be {key_size} bytes long")
            return

        iv = ct_bytes[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct_bytes[AES.block_size:]), AES.block_size).decode('utf-8')
        plaintext_text.delete("1.0", END)
        plaintext_text.insert(END, pt)
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI Setup
root = Tk()
root.title("AES Encryption / Decryption Tool")
root.geometry("800x500")

# Labels
Label(root, text="Plaintext").grid(row=0, column=0, padx=10, pady=5)
Label(root, text="Ciphertext (Base64)").grid(row=0, column=1, padx=10, pady=5)
Label(root, text="Secret Key").grid(row=2, column=0, padx=10, pady=5, sticky=W)
Label(root, text="Key Size (bytes)").grid(row=2, column=1, padx=10, pady=5, sticky=W)

# Text Areas
plaintext_text = scrolledtext.ScrolledText(root, width=40, height=10)
plaintext_text.grid(row=1, column=0, padx=10, pady=5)
ciphertext_text = scrolledtext.ScrolledText(root, width=40, height=10)
ciphertext_text.grid(row=1, column=1, padx=10, pady=5)

# Key Entry & Size Dropdown
key_entry = Entry(root, width=50, show="*")
key_entry.grid(row=3, column=0, columnspan=2, padx=10, pady=5)
key_size_var = StringVar(value="16")
key_size_menu = OptionMenu(root, key_size_var, "16", "24", "32")
key_size_menu.grid(row=3, column=2, padx=10, pady=5, sticky=W)

# Buttons
encrypt_btn = Button(root, text="Encrypt →", command=encrypt, width=20, bg="lightgreen")
encrypt_btn.grid(row=4, column=0, pady=10)
decrypt_btn = Button(root, text="← Decrypt", command=decrypt, width=20, bg="lightblue")
decrypt_btn.grid(row=4, column=1, pady=10)

root.mainloop()
