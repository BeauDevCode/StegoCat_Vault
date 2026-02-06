from PIL import Image
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import struct

class CryptoManager:
    """
    Handles RSA encryption and LSB Steganography using a Length-Prefix approach.
    This prevents data corruption by knowing exactly how many bytes to read.
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
        Embeds bytes into the image using a 32-bit Length Header.
        Structure: [32-bit Length][Encrypted Data Bits]
        """
        img = Image.open(image_path)
        img = img.convert("RGB") 
        pixels = list(img.getdata())

        # 1. Create the Length Header (4 bytes = 32 bits)
        # This tells the decoder exactly how big the message is.
        length_bytes = len(data).to_bytes(4, byteorder='big')
        
        # 2. Combine Length Header + Actual Data
        full_payload = length_bytes + data
        
        # 3. Convert to binary string
        binary_data = ''.join(format(byte, '08b') for byte in full_payload)
        
        if len(binary_data) > len(pixels) * 3:
            raise ValueError(f"Image too small! Needed {len(binary_data)} bits, but image has {len(pixels)*3}.")

        new_pixels = []
        data_index = 0
        
        for pixel in pixels:
            new_pixel = list(pixel)
            for i in range(3): # R, G, B
                if data_index < len(binary_data):
                    # Replace LSB with data bit
                    new_pixel[i] = (new_pixel[i] & ~1) | int(binary_data[data_index])
                    data_index += 1
            new_pixels.append(tuple(new_pixel))

        img.putdata(new_pixels)
        img.save(output_path, "PNG") 

    def reveal_data(self, image_path):
        """Extracts data by reading the Length Header first."""
        img = Image.open(image_path)
        pixels = list(img.getdata())
        
        # 1. Extract all LSBs into a massive binary generator
        all_bits = []
        for pixel in pixels:
            for color in pixel:
                all_bits.append(color & 1)
        
        # 2. Read the first 32 bits (Header) to get the message length
        header_bits = all_bits[:32]
        header_int = 0
        for bit in header_bits:
            header_int = (header_int << 1) | bit
            
        message_length_bytes = header_int
        message_length_bits = message_length_bytes * 8
        
        # Safety Check: Is the length reasonable?
        if message_length_bits > len(all_bits) - 32:
            raise ValueError("Corrupt header or no hidden message found.")

        # 3. Read exactly the number of bits we need
        payload_bits = all_bits[32 : 32 + message_length_bits]
        
        # 4. Convert bits back to bytes
        extracted_data = bytearray()
        current_byte = 0
        for i, bit in enumerate(payload_bits):
            current_byte = (current_byte << 1) | bit
            if (i + 1) % 8 == 0:
                extracted_data.append(current_byte)
                current_byte = 0
                
        return bytes(extracted_data)