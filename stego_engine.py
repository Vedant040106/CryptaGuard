import cv2
import numpy as np
import os

class StegoModule:
    def __init__(self):
        self.signature = "###SIG###"
        self.delimiter = "$$$EOF$$$"

    def encode(self, image_path, message, output_path):
        # 1. Read Image
        img = cv2.imread(image_path)
        if img is None: raise ValueError("Image not found")
        
        # 2. Prepare Payload (Vectorized)
        full_payload = self.signature + message + self.delimiter
        
        # Convert string to ASCII numbers, then to binary bits efficiently
        payload_bytes = np.array([ord(c) for c in full_payload], dtype=np.uint8)
        payload_bits = np.unpackbits(payload_bytes)
        
        # 3. Check Capacity
        flat_img = img.flatten()
        if len(payload_bits) > len(flat_img):
            raise ValueError(f"Message too long. Need {len(payload_bits)} pixels, have {len(flat_img)}")
            
        # 4. Embed Bits (Instant Operation)
        # Zero out the last bit of the pixels we need
        flat_img[:len(payload_bits)] &= 0xFE 
        # Add our payload bits to the LSB
        flat_img[:len(payload_bits)] |= payload_bits
        
        # 5. Reshape and Save
        encoded_img = flat_img.reshape(img.shape)
        cv2.imwrite(output_path, encoded_img)
        return True

    def decode(self, image_path):
        # 1. Read Image
        img = cv2.imread(image_path)
        if img is None: raise ValueError("Image not found")
        
        # 2. Extract LSBs (Vectorized - Instant)
        flat_img = img.flatten()
        # Get only the last bit of every pixel
        lsb_bits = flat_img & 1 
        
        # 3. Pack bits back into bytes
        bytes_data = np.packbits(lsb_bits)
        
        # 4. Convert to String
        # We use 'latin-1' to ensure 1-to-1 mapping of bytes to chars without crashing
        try:
            decoded_text = bytes_data.tobytes().decode('latin-1', errors='ignore')
        except:
            return False, "Binary data error."

        # 5. Fast Signature Check
        # We look for the signature immediately
        sig_index = decoded_text.find(self.signature)
        
        if sig_index != -1:
            # Signature found! Look for delimiter
            start = sig_index + len(self.signature)
            end = decoded_text.find(self.delimiter, start)
            
            if end != -1:
                return True, decoded_text[start:end]
        
        return False, "No hidden message detected."