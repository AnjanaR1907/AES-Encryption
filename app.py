from flask import Flask, request, render_template_string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
    <title>AES Encryption / Decryption Tool</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 900px; margin: auto; display: flex; flex-direction: column; }
        .columns { display: flex; gap: 20px; margin-bottom: 10px; }
        textarea { width: 100%; height: 150px; }
        input, select, button { padding: 8px; margin: 5px 0; width: 100%; }
        button { cursor: pointer; }
        .output { background: #f0f0f0; padding: 10px; word-wrap: break-word; }
        .column { flex: 1; display: flex; flex-direction: column; }
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
        <h2>AES Encryption / Decryption Tool</h2>

        <form method="POST">
            <label>Secret Key:</label>
            <input type="text" name="key" value="{{ request.form.key or '' }}" required>

            <label>Key Size (bytes):</label>
            <select name="key_size">
                <option value="16" {% if request.form.key_size=='16' %}selected{% endif %}>16</option>
                <option value="24" {% if request.form.key_size=='24' %}selected{% endif %}>24</option>
                <option value="32" {% if request.form.key_size=='32' %}selected{% endif %}>32</option>
            </select>

            <div class="columns">
                <div class="column">
                    <label>Plaintext:</label>
                    <textarea name="plaintext" id="plaintext">{{ request.form.plaintext or '' }}</textarea>
                    <button type="submit" name="action" value="encrypt" style="background: lightgreen;">Encrypt →</button>
                    <button type="button" onclick="copyToClipboard('plaintext')">Copy Plaintext</button>
                </div>
                <div class="column">
                    <label>Ciphertext (Base64):</label>
                    <textarea name="ciphertext" id="ciphertext">{{ output or '' }}</textarea>
                    <button type="submit" name="action" value="decrypt" style="background: lightblue;">← Decrypt</button>
                    <button type="button" onclick="copyToClipboard('ciphertext')">Copy Ciphertext</button>
                </div>
            </div>
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
