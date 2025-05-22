import streamlit as st
import json
import os
import time
import base64
import hashlib
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac

# --- Constants ---
USERS_FILE = "users.json"
LOCKOUT_FILE = "lockout.json"
SALT = b"streamlit_secure_salt"
LOCKOUT_THRESHOLD = 3
LOCKOUT_DURATION = 300  # seconds (5 minutes)

# --- Helpers for File I/O ---
def load_json(filepath):
    if os.path.exists(filepath):
        with open(filepath, "r") as f:
            return json.load(f)
    return {}

def save_json(filepath, data):
    with open(filepath, "w") as f:
        json.dump(data, f, indent=4)

# --- PBKDF2 Hashing ---
def hash_passkey_pbkdf2(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return base64.urlsafe_b64encode(key).decode()

# --- Encryption ---
def generate_cipher(user_key):
    return Fernet(user_key.encode())

def encrypt_data(text, cipher):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, cipher):
    return cipher.decrypt(encrypted_text.encode()).decode()

# --- User Auth ---
def authenticate_user(username, password, users):
    if username in users and users[username]["password"] == hash_passkey_pbkdf2(password):
        return True
    return False

# --- Lockout Logic ---
def is_locked_out(username, lockout_data):
    user_data = lockout_data.get(username, {})
    if user_data.get("attempts", 0) >= LOCKOUT_THRESHOLD:
        last_attempt = user_data.get("last_attempt", 0)
        if time.time() - last_attempt < LOCKOUT_DURATION:
            return True
    return False

def record_failed_attempt(username, lockout_data):
    user_data = lockout_data.get(username, {"attempts": 0, "last_attempt": 0})
    user_data["attempts"] += 1
    user_data["last_attempt"] = time.time()
    lockout_data[username] = user_data
    save_json(LOCKOUT_FILE, lockout_data)

def reset_attempts(username, lockout_data):
    if username in lockout_data:
        lockout_data[username] = {"attempts": 0, "last_attempt": 0}
        save_json(LOCKOUT_FILE, lockout_data)

# --- Load persisted data ---
users = load_json(USERS_FILE)
lockout_data = load_json(LOCKOUT_FILE)

# --- Streamlit UI ---
st.set_page_config(page_title="Secure Encryption App", page_icon="🔐")
st.title("🔐 Multi-User Secure Encryption System")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = ""
if "cipher" not in st.session_state:
    st.session_state.cipher = None

# --- Login or Register ---
if not st.session_state.logged_in:
    menu = st.sidebar.radio("Select Option", ["Login", "Register"])

    username = st.text_input("👤 Username")
    password = st.text_input("🔑 Password", type="password")

    if menu == "Login":
        if st.button("🔓 Login"):
            if is_locked_out(username, lockout_data):
                st.error("🚫 Too many failed attempts. Try again later.")
            elif authenticate_user(username, password, users):
                st.success("✅ Login successful!")
                st.session_state.logged_in = True
                st.session_state.username = username
                reset_attempts(username, lockout_data)
                st.session_state.cipher = generate_cipher(users[username]["key"])
            else:
                st.error("❌ Invalid credentials.")
                record_failed_attempt(username, lockout_data)

    elif menu == "Register":
        if st.button("📝 Register"):
            if username in users:
                st.warning("⚠️ Username already exists.")
            elif username and password:
                hashed = hash_passkey_pbkdf2(password)
                user_key = Fernet.generate_key().decode()
                users[username] = {"password": hashed, "key": user_key, "data": {}}
                save_json(USERS_FILE, users)
                st.success("✅ Registered successfully. Please log in.")
            else:
                st.warning("⚠️ Both fields are required.")

# --- Main App ---
if st.session_state.logged_in:
    menu = st.sidebar.selectbox("📂 Navigation", ["Home", "Store Data", "Retrieve Data", "Logout"])
    user_data = users[st.session_state.username]

    if menu == "Home":
        st.subheader(f"🏠 Welcome {st.session_state.username}!")
        st.write("Use this app to securely **encrypt** and **decrypt** your personal data.")

    elif menu == "Store Data":
        st.subheader("📥 Encrypt & Store Data")
        data = st.text_area("Enter your secret data:")
        if st.button("🔒 Encrypt & Save"):
            if data:
                encrypted = encrypt_data(data, st.session_state.cipher)
                user_data["data"][encrypted] = "stored"
                save_json(USERS_FILE, users)
                st.success("✅ Data encrypted and saved!")
                st.code(encrypted)
            else:
                st.warning("⚠️ Please enter some data.")

    elif menu == "Retrieve Data":
        st.subheader("🔍 Retrieve Encrypted Data")
        encrypted_text = st.text_area("Paste encrypted text:")
        if st.button("🔓 Decrypt"):
            if encrypted_text in user_data["data"]:
                try:
                    decrypted = decrypt_data(encrypted_text, st.session_state.cipher)
                    st.success("✅ Decrypted Data:")
                    st.code(decrypted)
                except Exception as e:
                    st.error("❌ Decryption failed. Invalid input.")
            else:
                st.error("❌ This encrypted text is not in your saved data.")

    elif menu == "Logout":
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.session_state.cipher = None
        st.success("✅ Logged out successfully.")
        st.rerun()

st.markdown("---")
st.caption("Developed with ❤️ using Python + Streamlit | Secure Encryption System")

