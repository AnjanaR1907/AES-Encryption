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
    # This is where errors like "Incorrect IV length" occur if data is corrupted.
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
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #06b6d4, #3b82f6);
            min-height: 100vh;
        }
    </style>
</head>
<body class="p-8 text-white">
    <div class="max-w-4xl mx-auto">
        <h1 class="text-3xl font-bold mb-8 text-center">🔐 AES Encryption & Decryption (CBC Mode)</h1>

        {% if error %}
        <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-xl mb-6 shadow-md" role="alert">
            <p class="font-bold">Operation Failed</p>
            <p>Cryptographic Error: {{ error }}</p>
        </div>
        {% endif %}

        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
            <!-- ENCRYPTION CARD -->
            <div class="bg-white p-6 rounded-xl shadow-2xl text-gray-800">
                <h2 class="text-xl font-semibold mb-4 text-blue-600">Encrypt Data</h2>
                <form method="POST" class="space-y-4">
                    <input type="hidden" name="action" value="encrypt">
                    <textarea name="plaintext" placeholder="Enter plaintext to encrypt..." required class="w-full p-3 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500">{{ encrypt_data.plaintext if encrypt_data.plaintext else "" }}</textarea>
                    <input type="text" name="key_input" placeholder="Enter secret key (16/24/32 bytes)" value="{{ encrypt_data.key_input if encrypt_data.key_input else '' }}" required class="w-full p-3 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500">
                    <button type="submit" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded-lg transition duration-150 transform hover:scale-[1.01] shadow-lg">Encrypt</button>
                </form>
                
                {% if encrypt_data.ciphertext %}
                <div class="mt-6 p-4 bg-blue-50 rounded-lg border border-blue-200">
                    <p class="font-bold text-blue-600 mb-2">Encryption Results:</p>
                    <p class="text-sm">Key (Hex): <span class="font-mono text-gray-700 break-all">{{ encrypt_data.secret_key }}</span></p>
                    <p class="text-sm">Key Length: <span class="font-bold text-gray-700">{{ encrypt_data.key_length }} bits</span></p>
                    <label class="block mt-3 text-sm font-medium text-gray-700">Initialization Vector (IV):</label>
                    <textarea readonly rows="2" id="iv_output" class="w-full p-2 text-sm font-mono bg-white border border-gray-300 rounded-lg mt-1 break-all">{{ encrypt_data.iv }}</textarea>
                    <label class="block mt-3 text-sm font-medium text-gray-700">Ciphertext:</label>
                    <textarea readonly rows="4" id="ct_output" class="w-full p-2 text-sm font-mono bg-white border border-gray-300 rounded-lg mt-1 break-all">{{ encrypt_data.ciphertext }}</textarea>
                </div>
                {% endif %}
            </div>
            
            <!-- DECRYPTION CARD -->
            <div class="bg-white p-6 rounded-xl shadow-2xl text-gray-800">
                <h2 class="text-xl font-semibold mb-4 text-pink-600">Decrypt Data</h2>
                <form method="POST" class="space-y-4">
                    <input type="hidden" name="action" value="decrypt">
                    <textarea name="iv_input" placeholder="Paste Base64 IV (16 bytes decoded)" required class="w-full p-3 border border-gray-300 rounded-lg focus:ring-pink-500 focus:border-pink-500">{{ decrypt_data.iv_input if decrypt_data.iv_input else "" }}</textarea>
                    <textarea name="ciphertext_input" placeholder="Paste Base64 Ciphertext" required class="w-full p-3 border border-gray-300 rounded-lg focus:ring-pink-500 focus:border-pink-500">{{ decrypt_data.ciphertext_input if decrypt_data.ciphertext_input else "" }}</textarea>
                    <input type="text" name="key_input" placeholder="Enter secret key (MUST be the EXACT same key)" value="{{ decrypt_data.key_input if decrypt_data.key_input else '' }}" required class="w-full p-3 border border-gray-300 rounded-lg focus:ring-pink-500 focus:border-pink-500">
                    <button type="submit" class="w-full bg-pink-600 hover:bg-pink-700 text-white font-bold py-2 rounded-lg transition duration-150 transform hover:scale-[1.01] shadow-lg">Decrypt</button>
                </form>

                {% if decrypt_data.plaintext %}
                <div class="mt-6 p-4 bg-pink-50 rounded-lg border border-pink-200">
                    <p class="font-bold text-pink-600 mb-2">Decryption Result:</p>
                    <label class="block text-sm font-medium text-gray-700">Decrypted Plaintext:</label>
                    <textarea readonly rows="4" class="w-full p-2 text-sm font-mono bg-white border border-gray-300 rounded-lg mt-1 break-all">{{ decrypt_data.plaintext }}</textarea>
                </div>
                {% endif %}
            </div>
        </div>
    </div>
</body>
</html>
"""

# ==============================
# Routes
# ==============================
@app.route("/", methods=["GET", "POST"])
def index():
    # Initial state or state after submission
    state = {'error': None, 'encrypt_data': {}, 'decrypt_data': {}}
    
    if request.method == "POST":
        action = request.form.get("action")
        key_input = request.form.get("key_input", "")
        user_key = key_input.encode('utf-8')
        
        # Preserve user key input
        if action == 'encrypt':
            state['encrypt_data']['key_input'] = key_input
            state['encrypt_data']['plaintext'] = request.form.get("plaintext", "")
        elif action == 'decrypt':
            state['decrypt_data']['key_input'] = key_input
            state['decrypt_data']['iv_input'] = request.form.get("iv_input", "")
            state['decrypt_data']['ciphertext_input'] = request.form.get("ciphertext_input", "")


        # --- Key Validation ---
        if len(user_key) not in (16, 24, 32):
            state['error'] = "❌ Invalid key length! Must be 16, 24, or 32 bytes (e.g., exactly 16 characters)."
            return render_template_string(html_page, **state)

        # --- Handle Encrypt Action ---
        if action == "encrypt":
            plaintext = request.form.get("plaintext", "")
            try:
                iv, ciphertext = aes_encrypt(plaintext, user_key)
                
                state['encrypt_data']['plaintext'] = plaintext
                state['encrypt_data']['secret_key'] = user_key.hex()
                state['encrypt_data']['key_length'] = len(user_key) * 8
                state['encrypt_data']['iv'] = iv
                state['encrypt_data']['ciphertext'] = ciphertext
                
            except ValueError as e:
                state['error'] = f"Encryption Error: {e}"
            except Exception as e:
                state['error'] = f"An unexpected error occurred during encryption: {e}"

        # --- Handle Decrypt Action ---
        elif action == "decrypt":
            iv_input = request.form.get("iv_input", "")
            ciphertext_input = request.form.get("ciphertext_input", "")
            
            try:
                # IMPORTANT: If the user provides a different key here, decryption will fail!
                decrypted_text = aes_decrypt(iv_input, ciphertext_input, user_key)
                
                state['decrypt_data']['plaintext'] = decrypted_text
                
            except ValueError as e:
                # This catches common errors like incorrect IV length, invalid padding, or invalid Base64.
                state['error'] = f"Decryption Failed (Key/IV/Ciphertext Error): {e}"
            except Exception as e:
                state['error'] = f"An unexpected error occurred during decryption: {e}"

        return render_template_string(html_page, **state)
                                    
    # --- Initial GET request ---
    return render_template_string(html_page, **state)

# ==============================
# Run
# ==============================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
