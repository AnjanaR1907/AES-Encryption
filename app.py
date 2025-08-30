from flask import Flask, request, render_template_string
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)

# ==============================
# AES Encryption / Decryption
# ==============================
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode()
    ct = base64.b64encode(ct_bytes).decode()
    return iv, ct

def aes_decrypt(iv, ciphertext, key):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

# ==============================
# HTML Template (inline)
# ==============================
html_page = """
<!DOCTYPE html>
<html>
<head>
    <title>🔐 AES Encryption Demo</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #9333EA, #3B82F6);
            text-align: center;
            padding: 40px;
            color: #fff;
        }
        h1 {
            font-size: 2.5em;
            margin-bottom: 20px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        form {
            background: #ffffff;
            color: #333;
            padding: 25px;
            border-radius: 20px;
            box-shadow: 0px 8px 16px rgba(0,0,0,0.2);
            display: inline-block;
            width: 75%;
            max-width: 700px;
        }
        textarea, input {
            width: 90%;
            padding: 12px;
            margin: 10px 0;
            border-radius: 12px;
            border: 1px solid #ccc;
            font-size: 1em;
        }
        button {
            background: #2563EB;
            color: white;
            border: none;
            padding: 12px 25px;
            margin-top: 10px;
            border-radius: 12px;
            cursor: pointer;
            font-size: 1em;
            transition: 0.3s;
        }
        button:hover {
            background: #1E40AF;
        }
        .result {
            background: rgba(255, 255, 255, 0.9);
            color: #222;
            margin-top: 25px;
            padding: 20px;
            border-radius: 20px;
            box-shadow: 0px 6px 12px rgba(0,0,0,0.2);
            text-align: left;
            display: inline-block;
            width: 75%;
            max-width: 700px;
            word-wrap: break-word;
        }
        .result b {
            color: #2563EB;
        }
    </style>
</head>
<body>
    <h1>🔐 AES Encryption & Decryption</h1>
    <form method="POST">
        <textarea name="plaintext" placeholder="Enter plaintext to encrypt..." required>{{ plaintext if plaintext else "" }}</textarea><br>
        <input type="text" name="user_key" placeholder="Enter custom AES key (16/24/32 bytes) or leave blank for random" value="{{ user_key if user_key else '' }}"><br>
        <button type="submit">Encrypt & Decrypt</button>
    </form>

    {% if secret_key %}
    <div class="result">
        <p><b>Secret Key (Hex):</b><br>{{ secret_key }}</p>
        <p><b>Key Length (bits):</b> {{ key_length }}</p>
        <p><b>Ciphertext (Base64):</b><br>{{ ciphertext }}</p>
        <p><b>Decrypted Plaintext:</b><br>{{ decrypted_text }}</p>
    </div>
    {% endif %}
</body>
</html>
"""

# ==============================
# Routes
# ==============================
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        plaintext = request.form["plaintext"]
        user_key = request.form.get("user_key")

        # If user provided a key → use it, else generate random
        if user_key and len(user_key.encode()) in (16, 24, 32):
            key = user_key.encode()
        elif user_key:
            return render_template_string(html_page, plaintext=plaintext, user_key=user_key,
                                          secret_key="❌ Invalid key length! Must be 16/24/32 bytes.",
                                          ciphertext="", decrypted_text="", key_length="Invalid")
        else:
            key = get_random_bytes(16)  # default AES-128

        iv, ciphertext = aes_encrypt(plaintext, key)
        decrypted_text = aes_decrypt(iv, ciphertext, key)

        return render_template_string(
            html_page,
            plaintext=plaintext,
            user_key=user_key,
            secret_key=key.hex(),
            key_length=len(key)*8,
            ciphertext=ciphertext,
            decrypted_text=decrypted_text
        )
    return render_template_string(html_page)

# ==============================
# Run
# ==============================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
