# 🐱🔒 StegoCat Vault
### RSA Encrypted Steganography Tool

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-success)

**StegoCat Vault** is a secure communication tool that combines **Asymmetric Cryptography (RSA)** with **Least Significant Bit (LSB) Steganography**.

It allows users to encrypt text messages using a recipient's Public Key and hide the encrypted binary data inside the pixels of an image (like a cat sprite). The resulting image looks identical to the original but contains a hidden payload that can only be unlocked with the matching Private Key.

---

## 📸 Screenshots

| 1. Key Management | 2. Encryption (Hiding) | 3. Decryption (Revealing) |
|:---:|:---:|:---:|
| ![Keys Tab](screenshots/keys.png) | ![Encrypt Tab](screenshots/encrypt.png) | ![Decrypt Tab](screenshots/decrypt.png) |<img width="923" height="708" alt="keys" src="https://github.com/user-attachments/assets/bdadf0d9-30a5-4305-8853-6c5a9173bcb5" />


---

## ✨ Key Features

* **🔑 RSA-2048 Identity System:** Generates industry-standard PEM formatted Public/Private key pairs.
* **🖼️ LSB Steganography:** Injects data into the bits of the image pixels, modifying the Blue/Green channels imperceptibly.
* **📏 Header-Based Data Protocol:** Uses a 32-bit Length Header to ensure data integrity and prevent corruption during extraction.
* **🌑 Modern Dark UI:** Built with `customtkinter` for a responsive, high-DPI friendly interface.
* **🛡️ Lossless Output:** Enforces PNG format to prevent compression artifacts from destroying hidden data.

---

## 🛠️ Installation

### Prerequisites
* Python 3.10 or higher
* pip (Python Package Manager)

### Setup
1.  Install the required dependencies:
    ```bash
    pip install customtkinter Pillow cryptography
    ```

2.  Run the application:
    ```bash
    python main.py
    ```

---

## 🚀 How to Use

### Step 1: Establish Identity
1.  Go to the **Key Management** tab.
2.  Click **Generate New Key Pair**.
3.  Save your `private_key.pem` (Keep this safe!) and `public_key.pem` (Share this one).

### Step 2: Hide a Secret (Encrypt)
1.  Go to the **Hide (Encrypt)** tab.
2.  **Load Public Key:** Select the `public_key.pem` of the person you want to message.
3.  **Type Message:** Enter your secret text.
4.  **Encrypt:** Select a clean source image (PNG/JPG). The app will save a new Encoded PNG.

### Step 3: Reveal a Secret (Decrypt)
1.  Go to the **Reveal (Decrypt)** tab.
2.  **Load Private Key:** Select your own `private_key.pem`.
3.  **Decrypt:** Select the Encoded PNG image.
4.  The hidden text will appear in the output box.

---

## 🧠 Technical Deep Dive

### The "Header" Protocol
Early versions of this tool used a delimiter string to mark the end of a message, which caused corruption if the encrypted binary contained that specific string pattern.

**The Solution:** This tool implements a **Length-Prefix Protocol**.
1.  **Header:** The first 32 pixels of the image contain the *exact length* of the message in binary.
2.  **Payload:** The application reads the header first, determines it needs to read exactly $N$ bits, and then stops.
3.  **Result:** 100% reliable decryption with no "garbage bytes" at the end.

### The Math
The embedding process uses bitwise operators to modify the pixel values:
```python
# Clear the last bit (LSB) and OR it with the data bit
new_pixel_value = (old_pixel_value & ~1) | data_bit
