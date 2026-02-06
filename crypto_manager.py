from PIL import Image
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

class CryptoManager:
    """
    Handles RSA encryption operations and LSB (Least Significant Bit) 
    image steganography.
    """
    
    def generate_keys(self):
        """Generates a fresh 2048-bit RSA Private/Public key pair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def save_key(self, key, filename, is_private=False):
        """Saves keys to PEM format files."""
        if is_private:
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        else:
            pem = key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        with open(filename, 'wb') as f:
            f.write(pem)

    def load_key(self, filename, is_private=False):
        """Loads keys from PEM files."""
        with open(filename, "rb") as key_file:
            if is_private:
                return serialization.load_pem_private_key(key_file.read(), password=None)
            else:
                return serialization.load_pem_public_key(key_file.read())

    def encrypt_message(self, message, public_key):
        """Encrypts a string message into bytes using the recipient's Public Key."""
        ciphertext = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt_message(self, ciphertext, private_key):
        """Decrypts bytes back into a string using your Private Key."""
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()

    def hide_data(self, image_path, data, output_path):
        """
        Embeds bytes into the image pixels using LSB Steganography.
        """
        img = Image.open(image_path)
        img = img.convert("RGB") 
        pixels = list(img.getdata())

        # Convert data bytes to a binary string (e.g., '010110...')
        binary_data = ''.join(format(byte, '08b') for byte in data)
        
        # Add a 16-bit delimiter so we know exactly where the message ends
        # Delimiter pattern: 1111111111111110
        binary_data += '1111111111111110' 
        
        if len(binary_data) > len(pixels) * 3:
            raise ValueError("Error: Image is too small to hold this much data.")

        new_pixels = []
        data_index = 0
        
        for pixel in pixels:
            new_pixel = list(pixel)
            # Modify R, G, B channels
            for i in range(3): 
                if data_index < len(binary_data):
                    # Bitwise operation to replace the last bit
                    new_pixel[i] = (new_pixel[i] & ~1) | int(binary_data[data_index])
                    data_index += 1
            new_pixels.append(tuple(new_pixel))

        img.putdata(new_pixels)
        # Saving as PNG is CRITICAL because JPEG compression destroys LSB data
        img.save(output_path, "PNG") 

    def reveal_data(self, image_path):
        """Extracts hidden LSB data from an image."""
        img = Image.open(image_path)
        pixels = list(img.getdata())
        
        binary_data = ""
        for pixel in pixels:
            for color in pixel:
                binary_data += str(color & 1)

        # Split binary string into 8-bit chunks (bytes)
        all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
        
        extracted_data = bytearray()
        for byte in all_bytes:
            if byte == '11111110': # Delimiter found! Stop reading.
                break
            extracted_data.append(int(byte, 2))
            
        return bytes(extracted_data)