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

        <label>Secret Key:</label>
        <input type="text" name="key" id="key" value="{{ request.form.key or '' }}">

        <label>Key Size (bytes):</label>
        <select id="key_size">
            <option value="16" {% if request.form.key_size=='16' %}selected{% endif %}>16</option>
            <option value="24" {% if request.form.key_size=='24' %}selected{% endif %}>24</option>
            <option value="32" {% if request.form.key_size=='32' %}selected{% endif %}>32</option>
        </select>

        <div class="columns">
            <div class="column">
                <label>Plaintext:</label>
                <textarea id="plaintext">{{ request.form.text or '' }}</textarea>
                <button onclick="encryptText()" style="background: lightgreen;">Encrypt →</button>
                <button onclick="copyToClipboard('plaintext')">Copy Plaintext</button>
            </div>
            <div class="column">
                <label>Ciphertext (Base64):</label>
                <textarea id="ciphertext">{{ output or '' }}</textarea>
                <button onclick="decryptText()" style="background: lightblue;">← Decrypt</button>
                <button onclick="copyToClipboard('ciphertext')">Copy Ciphertext</button>
            </div>
        </div>
    </div>

    <script>
        async function encryptText() {
            const key = document.getElementById("key").value;
            const key_size = document.getElementById("key_size").value;
            const text = document.getElementById("plaintext").value;

            const response = await fetch("/", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ action: "encrypt", key, key_size, text })
            });
            const data = await response.json();
            document.getElementById("ciphertext").value = data.output;
        }

        async function decryptText() {
            const key = document.getElementById("key").value;
            const key_size = document.getElementById("key_size").value;
            const text = document.getElementById("ciphertext").value;

            const response = await fetch("/", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ action: "decrypt", key, key_size, text })
            });
            const data = await response.json();
            document.getElementById("plaintext").value = data.output;
        }
    </script>
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
    data = request.get_json()
    if data:
        action = data.get("action")
        text = data.get("text", "")
        key = data.get("key", "").encode()
        key_size = int(data.get("key_size", 16))

        if len(key) != key_size:
            output = f"Error: Key must be {key_size} bytes long"
        else:
            try:
                if action == "encrypt":
                    output = encrypt_aes(text.encode(), key)
                elif action == "decrypt":
                    output = decrypt_aes(text, key)
            except Exception as e:
                output = f"Error: {str(e)}"
        return {"output": output}

    return render_template_string(HTML_PAGE, output=output)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
