from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import base64
from Crypto.Hash import SHA256


size = 1024


def generate_rsa_keys():
    key_length = size
    private_key = RSA.generate(key_length, Random.new().read)
    public_key = private_key.publickey()
    return private_key, public_key

def encrypt_rsa(public_key, plain_text):
    cipher = PKCS1_OAEP.new(public_key)
    cipher_text = cipher.encrypt(plain_text)
    return base64.b64encode(cipher_text)

def decrypt_rsa(private_key, cipher_text):
    decoded_ciphertext = base64.b64decode(cipher_text)
    plain_text = private_key.decrypt(decoded_ciphertext)
    return plain_text

def create_signature(private_key, data):
    h = SHA256.new(data)
    signature = pkcs1_15.new(private_key).sign(h)
    return base64.b64encode(signature)

def verify_signature(public_key, data, signature):
    h = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, base64.b64decode(signature))
        return True
    except (ValueError, TypeError):
        return False

if __name__=='__main__':
    private_key, public_key = generate_rsa_keys()
    message = b'This is a test message.'
    
    # Encryption and Decryption
    encrypted_message = encrypt_rsa(public_key, message)
    decrypted_message = decrypt_rsa(private_key, encrypted_message)
    print("Original message:", message.decode())
    print("Decrypted message:", decrypted_message.decode())
    
    # Signing and Verification
    signature = create_signature(private_key, message)
    print("Signature:", signature.decode())
    print("Verification result:", verify_signature(public_key, message, signature))
