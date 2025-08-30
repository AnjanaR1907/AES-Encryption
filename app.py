from flask import Flask, request, render_template_string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>Colorful AES Encryption Tool</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f2f8ff; margin: 30px; }
        .container { max-width: 700px; margin: auto; background: #ffffff; padding: 30px; border-radius: 15px; 
                     box-shadow: 0px 0px 15px rgba(0,0,0,0.2);}
        h2 { text-align: center; color: #2a52be; }
        label { font-weight: bold; margin-top: 10px; display: block; color: #333; }
        textarea { width: 100%; height: 120px; margin-top: 5px; border-radius: 8px; padding: 10px; border: 2px solid #2a52be; }
        input, select { padding: 10px; margin-top: 5px; border-radius: 8px; border: 2px solid #2a52be; width: 100%; }
        button { padding: 10px; border: none; border-radius: 8px; cursor: pointer; font-weight: bold; margin-top: 10px; }
        .encrypt-btn { background-color: #4CAF50; color: white; width: 48%; margin-right: 2%; }
        .decrypt-btn { background-color: #2196F3; color: white; width: 48%; }
        .output { margin-top: 15px; background: #f1f1f1; padding: 15px; border-radius: 8px; word-wrap: break-word; border: 2px solid #2a52be; }
    </style>
    <script>
        function copyToClipboard(id) {
            var copyText = document.getElementById(id);
            copyText.select();
            copyText.setSelectionRange(0, 99999);
            navigator.clipboard.writeText(copyText.value);
            alert("Copied to clipboard!");
        }
    </script>
</head>
<body>
    <div class="container">
        <h2>Colorful AES Encryption / Decryption Tool</h2>
        <form method="POST">
            <label>Plaintext:</label>
            <textarea name="plaintext" id="plaintext">{{ request.form.plaintext or '' }}</textarea>

            <label>Key Size (bytes):</label>
            <select name="key_size">
                <option value="16" {% if request.form.key_size=='16' %}selected{% endif %}>16</option>
                <option value="24" {% if request.form.key_size=='24' %}selected{% endif %}>24</option>
                <option value="32" {% if request.form.key_size=='32' %}selected{% endif %}>32</option>
            </select>

            <label>Secret Key:</label>
            <input type="text" name="key" value="{{ request.form.key or '' }}" required>

            <button type="submit" name="action" value="encrypt" class="encrypt-btn">Encrypt →</button>
            <button type="submit" name="action" value="decrypt" class="decrypt-btn">← Decrypt</button>

            <label>Ciphertext (Base64):</label>
            <textarea id="ciphertext">{{ output or '' }}</textarea>
            <button type="button" onclick="copyToClipboard('ciphertext')" style="background-color:#ff9800; color:white; width: 100%; margin-top:5px;">Copy Ciphertext</button>
        </form>
    </div>
</body>
</html>
"""

def encrypt_aes(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')

def decrypt_aes(ciphertext, key):
    ct_bytes = base64.b64decode(ciphertext)
    iv = ct_bytes[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct_bytes[AES.block_size:]), AES.block_size)
    return pt.decode('utf-8')

@app.route("/", methods=["GET", "POST"])
def index():
    output = ""
    if request.method == "POST":
        key = request.form.get("key", "").encode()
        key_size = int(request.form.get("key_size", 16))
        action = request.form.get("action")
        plaintext = request.form.get("plaintext", "")
        ciphertext = request.form.get("ciphertext", "")

        if len(key) != key_size:
            output = f"Error: Key must be {key_size} bytes long"
        else:
            try:
                if action == "encrypt":
                    output = encrypt_aes(plaintext.encode(), key)
                elif action == "decrypt":
                    output = decrypt_aes(ciphertext, key)
            except Exception as e:
                output = f"Error: {str(e)}"

    return render_template_string(HTML_PAGE, output=output)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
