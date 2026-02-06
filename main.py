import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
from crypto_manager import CryptoManager

# --- App Configuration ---
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

class StegoApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("StegoCat :: RSA Pixel Vault")
        self.geometry("750x550")
        
        # Initialize Logic
        self.crypto = CryptoManager()
        self.loaded_public_key = None
        self.loaded_private_key = None
        
        # UI Layout
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=20)
        
        self.tab_keys = self.tabview.add("1. Key Management")
        self.tab_encrypt = self.tabview.add("2. Hide (Encrypt)")
        self.tab_decrypt = self.tabview.add("3. Reveal (Decrypt)")
        
        self._setup_keys_tab()
        self._setup_encrypt_tab()
        self._setup_decrypt_tab()

    def _setup_keys_tab(self):
        """UI for generating keys."""
        frame = ctk.CTkFrame(self.tab_keys)
        frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        title = ctk.CTkLabel(frame, text="RSA Identity Setup", font=ctk.CTkFont(size=20, weight="bold"))
        title.pack(pady=(30, 10))
        
        desc = ctk.CTkLabel(frame, text="Generate a Key Pair to start.\nSend your PUBLIC key to friends.\nKeep your PRIVATE key secret.", text_color="gray")
        desc.pack(pady=10)
        
        btn = ctk.CTkButton(frame, text="Generate New Key Pair", command=self.generate_keys_ui, height=40)
        btn.pack(pady=20)

    def _setup_encrypt_tab(self):
        """UI for hiding messages."""
        frame = ctk.CTkFrame(self.tab_encrypt)
        frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        self.lbl_pub_status = ctk.CTkLabel(frame, text="Status: No Public Key Loaded", text_color="red")
        self.lbl_pub_status.pack(pady=5)
        
        ctk.CTkButton(frame, text="Load Recipient's Public Key", command=self.load_public_key_ui).pack(pady=5)
        
        ctk.CTkLabel(frame, text="Secret Message:", anchor="w").pack(fill="x", padx=20, pady=(20, 0))
        self.enc_msg_entry = ctk.CTkEntry(frame, placeholder_text="Type your secret message here...")
        self.enc_msg_entry.pack(pady=5, padx=20, fill="x")
        
        ctk.CTkButton(frame, text="Select Image & Encrypt", command=self.encode_ui, fg_color="green", height=40).pack(pady=30)

    def _setup_decrypt_tab(self):
        """UI for revealing messages."""
        frame = ctk.CTkFrame(self.tab_decrypt)
        frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        self.lbl_priv_status = ctk.CTkLabel(frame, text="Status: No Private Key Loaded", text_color="red")
        self.lbl_priv_status.pack(pady=5)
        
        ctk.CTkButton(frame, text="Load Your Private Key", command=self.load_private_key_ui).pack(pady=5)
        
        ctk.CTkButton(frame, text="Select Encoded Image & Decrypt", command=self.decode_ui, fg_color="green", height=40).pack(pady=20)
        
        ctk.CTkLabel(frame, text="Decrypted Output:", anchor="w").pack(fill="x", padx=20)
        self.dec_output = ctk.CTkTextbox(frame, height=100)
        self.dec_output.pack(pady=5, padx=20, fill="x")

    # --- Interaction Logic ---
    
    def generate_keys_ui(self):
        priv, pub = self.crypto.generate_keys()
        
        # Save Private Key
        file_path_priv = filedialog.asksaveasfilename(defaultextension=".pem", initialfile="my_private_key.pem", title="Save Private Key")
        if not file_path_priv: return
        self.crypto.save_key(priv, file_path_priv, is_private=True)
        
        # Save Public Key
        file_path_pub = filedialog.asksaveasfilename(defaultextension=".pem", initialfile="my_public_key.pem", title="Save Public Key")
        if not file_path_pub: return
        self.crypto.save_key(pub, file_path_pub, is_private=False)
        
        messagebox.showinfo("Success", "Keys generated successfully!")

    def load_public_key_ui(self):
        path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
        if path:
            try:
                self.loaded_public_key = self.crypto.load_key(path, is_private=False)
                self.lbl_pub_status.configure(text=f"Loaded: {os.path.basename(path)}", text_color="green")
            except Exception:
                messagebox.showerror("Error", "Invalid Public Key file.")

    def load_private_key_ui(self):
        path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
        if path:
            try:
                self.loaded_private_key = self.crypto.load_key(path, is_private=True)
                self.lbl_priv_status.configure(text=f"Loaded: {os.path.basename(path)}", text_color="green")
            except Exception:
                messagebox.showerror("Error", "Invalid Private Key file.")

    def encode_ui(self):
        if not self.loaded_public_key:
            messagebox.showerror("Error", "You must load a Public Key first!")
            return
            
        msg = self.enc_msg_entry.get()
        if not msg:
            messagebox.showerror("Error", "Please enter a message to hide.")
            return

        img_path = filedialog.askopenfilename(title="Select Source Image", filetypes=[("Images", "*.png;*.jpg;*.jpeg")])
        if not img_path: return
        
        save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")], title="Save Encoded Image")
        if not save_path: return
        
        try:
            # 1. RSA Encrypt
            encrypted_bytes = self.crypto.encrypt_message(msg, self.loaded_public_key)
            # 2. LSB Steganography
            self.crypto.hide_data(img_path, encrypted_bytes, save_path)
            messagebox.showinfo("Success", f"Secret saved to {os.path.basename(save_path)}")
        except ValueError as ve:
            messagebox.showerror("Error", str(ve))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to encode: {str(e)}")

    def decode_ui(self):
        if not self.loaded_private_key:
            messagebox.showerror("Error", "You must load your Private Key first!")
            return

        img_path = filedialog.askopenfilename(title="Select Encoded Image", filetypes=[("PNG Image", "*.png")])
        if not img_path: return
        
        try:
            # 1. LSB Extract
            encrypted_bytes = self.crypto.reveal_data(img_path)
            # 2. RSA Decrypt
            plaintext = self.crypto.decrypt_message(encrypted_bytes, self.loaded_private_key)
            
            self.dec_output.delete("0.0", "end")
            self.dec_output.insert("0.0", plaintext)
        except Exception:
            messagebox.showerror("Failure", "Decryption failed.\nPossible causes:\n1. Wrong Private Key\n2. Image has no secret data\n3. Image was compressed/altered")

if __name__ == "__main__":
    app = StegoApp()
    app.mainloop()