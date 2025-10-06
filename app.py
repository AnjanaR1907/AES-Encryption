from flask import Flask, request, render_template_string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)

# ==============================
# AES Functions
# ==============================
def aes_encrypt(plaintext, key):
    """Encrypts plaintext using AES-CBC, returns base64 encoded IV and ciphertext."""
    # AES.new generates a random 16-byte IV when IV is not provided.
    cipher = AES.new(key, AES.MODE_CBC)
    # 1. Pad and encrypt the plaintext bytes.
    ct_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    # 2. Base64 encode the binary IV and ciphertext for safe transport/display.
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv, ct

def aes_decrypt(iv_b64, ciphertext_b64, key):
    """Decrypts base64 IV and ciphertext using AES-CBC, returns plaintext string."""
    # 1. Decode Base64 strings back to binary bytes.
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(ciphertext_b64)
    
    # 2. Re-initialize cipher with the key and the received IV.
    # This is the line that throws "Incorrect IV length" if len(iv) != 16
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # 3. Decrypt and unpad
    pt_padded = cipher.decrypt(ct)
    pt = unpad(pt_padded, AES.block_size)
    
    # 4. Decode bytes back to UTF-8 string
    return pt.decode('utf-8')

# ==============================
# HTML Template (inline)
# ==============================
html_page = """
<!DOCTYPE html>
<html>
<head>
    <title>🔐 AES Encryption & Decryption</title>
    <style>
        body {
            font-family: 'Inter', 'Segoe UI', Arial, sans-serif;
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
            box-shadow: 0 4px #1E40AF;
        }
        button:hover { background: #1E40AF; box-shadow: 0 2px #1E40AF; transform: translateY(2px); }
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
        .result pre { 
            background: #f4f4f4; 
            padding: 10px; 
            border-radius: 8px; 
            overflow-x: auto; 
            white-space: pre-wrap;
        }
    </style>
</head>
<body>
    <h1>🔐 AES Encryption & Decryption (CBC Mode)</h1>
    <form method="POST">
        <textarea name="plaintext" placeholder="Enter plaintext..." required>{{ plaintext if plaintext else "" }}</textarea><br>
        <input type="text" name="user_key" placeholder="Enter secret key (16/24/32 bytes)" value="{{ user_key if user_key else '' }}" required><br>
        <button type="submit">Encrypt & Decrypt</button>
    </form>

    {% if error %}
    <div class="result">
        <p style="color:red;"><b>Error:</b> {{ error }}</p>
    </div>
    {% endif %}

    {% if secret_key %}
    <div class="result">
        <p><b>Secret Key (Hex):</b><br><pre>{{ secret_key }}</pre></p>
        <p><b>Key Length (bits):</b> {{ key_length }}</p>
        <p><b>Ciphertext (Base64 + IV):</b><br><pre>{{ ciphertext }}</pre></p>
        <p><b>Decrypted Plaintext:</b><br><pre>{{ decrypted_text }}</pre></p>
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
        plaintext = request.form.get("plaintext", "")
        key_input = request.form.get("user_key", "")
        
        # --- Key Encoding and Validation ---
        user_key = key_input.encode('utf-8')
        
        if len(user_key) not in (16, 24, 32):
            return render_template_string(html_page,
                                         plaintext=plaintext,
                                         user_key=key_input,
                                         error="❌ Invalid key length! Must be 16, 24, or 32 bytes.")

        # --- Encryption & Decryption ---
        error_message = None
        ciphertext = ""
        decrypted_text = ""
        
        try:
            # ENCRYPTION: Returns Base64-encoded IV and Ciphertext
            iv, ciphertext_data = aes_encrypt(plaintext, user_key)
            
            # Combine IV and Ciphertext for display/storage (IV is prepended to the ciphertext data for simplicity)
            # NOTE: In real-world applications, you'd typically send IV and CT separately.
            ciphertext = f"IV={iv}\nCT={ciphertext_data}"

            # DECRYPTION: Uses the exact same key and IV to verify integrity
            # Pass the separate components back to the decrypt function
            decrypted_text = aes_decrypt(iv, ciphertext_data, user_key)
            
        except ValueError as e:
            # Catches IV length errors, Padding errors, and other cryptographic value issues
            error_message = f"Cryptographic Error: {e}"
        except Exception as e:
            # Catches other unexpected errors
            error_message = f"An unexpected error occurred: {e}"

        if error_message:
             return render_template_string(html_page,
                                         plaintext=plaintext,
                                         user_key=key_input,
                                         error=error_message)

        # --- Success Output ---
        return render_template_string(html_page,
                                    plaintext=plaintext,
                                    user_key=key_input,
                                    secret_key=user_key.hex(),
                                    key_length=len(user_key)*8,
                                    ciphertext=ciphertext,
                                    decrypted_text=decrypted_text)
                                    
    # --- Initial GET request ---
    return render_template_string(html_page)

# ==============================
# Run
# ==============================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
