from flask import Flask, request, render_template_string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64, os

app = Flask(__name__)

# ==============================
# AES Functions
# ==============================
def aes_encrypt(plaintext, key, iv=None):
    if iv is None:
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
    else:
        iv = bytes.fromhex(iv)
        cipher = AES.new(key, AES.MODE_CBC, iv)

    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    iv_b64 = base64.b64encode(iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv_b64, ct

def aes_decrypt(iv, ciphertext, key):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

# ==============================
# HTML Template
# ==============================
html_page = """
<!DOCTYPE html>
<html>
<head>
    <title>🔐 AES Encryption & Decryption</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #06b6d4, #3b82f6);
            text-align: center;
            padding: 40px;
            color: #fff;
        }
        h1 { font-size: 2.2em; margin-bottom: 20px; }
        form {
            background: #ffffff;
            color: #222;
            padding: 25px;
            border-radius: 16px;
            box-shadow: 0px 8px 16px rgba(0,0,0,0.2);
            display: inline-block;
            width: 75%;
            max-width: 650px;
        }
        textarea, input {
            width: 90%;
            padding: 12px;
            margin: 8px 0;
            border-radius: 10px;
            border: 1px solid #ccc;
            font-size: 1em;
        }
        button {
            background: #2563EB;
            color: white;
            border: none;
            padding: 12px 25px;
            margin-top: 10px;
            border-radius: 10px;
            cursor: pointer;
            font-size: 1em;
            transition: 0.3s;
        }
        button:hover { background: #1E40AF; }
        .result {
            background: rgba(255, 255, 255, 0.95);
            color: #111;
            margin-top: 25px;
            padding: 20px;
            border-radius: 16px;
            box-shadow: 0px 6px 12px rgba(0,0,0,0.2);
            text-align: left;
            width: 75%;
            max-width: 650px;
            margin-left: auto;
            margin-right: auto;
            word-wrap: break-word;
        }
        .result b { color: #2563EB; }
    </style>
</head>
<body>
    <h1>🔐 AES Encryption & Decryption (CBC Mode)</h1>
    <form method="POST">
        <textarea name="plaintext" placeholder="Enter plaintext..." required>{{ plaintext if plaintext else "" }}</textarea><br>
        <input type="text" name="user_key" placeholder="Enter secret key (16/24/32 bytes)" value="{{ user_key if user_key else '' }}" required><br>
        <input type="text" name="user_iv" placeholder="Enter IV in hex (32 chars) or leave blank for random" value="{{ user_iv if user_iv else '' }}"><br>
        <button type="submit">Encrypt & Decrypt</button>
    </form>

    {% if error %}
    <div class="result">
        <p style="color:red;"><b>Error:</b> {{ error }}</p>
    </div>
    {% endif %}

    {% if secret_key %}
    <div class="result">
        <p><b>Secret Key (Hex):</b><br>{{ secret_key }}</p>
        <p><b>Key Length (bits):</b> {{ key_length }}</p>
        <p><b>IV (Base64):</b><br>{{ iv }}</p>
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
        user_key = request.form["user_key"].encode()
        user_iv = request.form["user_iv"]

        # Validate key length
        if len(user_key) not in (16, 24, 32):
            return render_template_string(html_page,
                                          plaintext=plaintext,
                                          user_key=request.form["user_key"],
                                          user_iv=user_iv,
                                          error="❌ Invalid key length! Must be 16, 24, or 32 bytes.")

        # Validate IV if provided
        if user_iv and len(user_iv) != 32:
            return render_template_string(html_page,
                                          plaintext=plaintext,
                                          user_key=request.form["user_key"],
                                          user_iv=user_iv,
                                          error="❌ Invalid IV length! Must be 32 hex characters (16 bytes).")

        iv, ciphertext = aes_encrypt(plaintext, user_key, user_iv if user_iv else None)
        decrypted_text = aes_decrypt(iv, ciphertext, user_key)

        return render_template_string(html_page,
                                      plaintext=plaintext,
                                      user_key=request.form["user_key"],
                                      user_iv=user_iv,
                                      secret_key=user_key.hex(),
                                      key_length=len(user_key)*8,
                                      iv=iv,
                                      ciphertext=ciphertext,
                                      decrypted_text=decrypted_text)
    return render_template_string(html_page)

# ==============================
# Run
# ==============================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
