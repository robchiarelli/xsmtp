'''
AES_128_gcm(msg, key, IV) + RSA_public_encrypt(key) + IV + RSA_digital_sign
where AES is using a random key and IV every time
RSA public encrypt is encrypting using the recipients public key
and RSA_digital_sign is creating a digital signature with senders private key

https://en.wikipedia.org/wiki/Galois/Counter_Mode
https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.GCM

'''
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
import cryptography.hazmat.backends as backends
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption, KeySerializationEncryption, load_pem_private_key, load_pem_public_key
from cryptography.exceptions import InvalidSignature
import os
import sys

def AES_gcm_encrypt(key, plaintext, associated_data=None):
    iv = os.urandom(12)

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend= backends.default_backend()
    ).encryptor()
    if associated_data:
        encryptor.authenticate_additional_data(associated_data)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (iv, ciphertext, encryptor.tag)

def AES_gcm_decrypt(key, ciphertext, iv, tag, associated_data=None):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend= backends.default_backend()
    ).decryptor()
    if associated_data:
        decryptor.authenticate_additional_data(associated_data)
    return decryptor.update(ciphertext) + decryptor.finalize()

def RSA_keygen():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

def RSA_save_key(rsakey):
    f = open("key.pub", "w")
    f.write(rsakey.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    f.close()
    f = open("key.priv", "w")
    f.write(rsakey.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
    f.close()

def RSA_load_key():
    key_file = open("key.priv", "rb")
    return load_pem_private_key(
        key_file.read(),
        password=None,
        backend=default_backend()
    )

def RSA_load_pub(username):
    key_file = open(username + ".pub", "rb")
    return load_pem_public_key(key_file.read(), default_backend())

def RSA_sign(data, private_key):
    signer = private_key.signer(
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signer.update(data)
    return signer.finalize()

def RSA_verify(message, sig, public_key):
    verifier = public_key.verifier(
        sig,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    verifier.update(message)
    try:
        verifier.verify()
    except cryptography.exceptions.InvalidSignature:
        return False
    return True


def RSA_encrypt(data, pubkey):
    return pubkey.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None)
    )

def RSA_decrypt(data, prikey):
    return prikey.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

def gen_payload(rsa_sig, enc_aeskey, iv, tag, ciphertext):
    return rsa_sig.encode('hex') + '$' + enc_aeskey.encode('hex') + '$' + iv.encode('hex') + '$' + tag.encode('hex') + '$' + ciphertext.encode('hex')

def rec_payload(payload):
    import pdb
    pdb.set_trace()
    parts = [x.decode('hex') for x in payload.split('$')]
    return tuple(parts)

def hybrid_encrypt(msg, pubkey, prikey):
    aeskey = os.urandom(16)
    ek = RSA_encrypt(aeskey, pubkey)
    iv, ciphertext, tag = AES_gcm_encrypt(aeskey, msg)
    sig = RSA_sign(iv + ek + tag, prikey)
    return gen_payload(sig, ek, iv, tag, ciphertext)

def hybrid_decrypt(msg, pubkey, prikey):
    sig, ek, iv, tag, ciphertext = rec_payload(msg)
    if(RSA_verify(iv + ek + tag, sig, pubkey)):
        aeskey = RSA_decrypt(ek, prikey)
        dec = AES_gcm_decrypt(aeskey, ciphertext, iv, tag)
        return dec
    else:
        return ""


#rsakey = RSA.generate(2048, e=65537)
#public key

if sys.argv[1] == "keygen":
    RSA_save_key(RSA_keygen())
elif sys.argv[1] == "encrypt":
    pub = RSA_load_pub(sys.argv[2])
    pri = RSA_load_key()
    e = hybrid_encrypt(sys.argv[3], pub, pri)
    out = open("enc", "wb")
    out.write(e)
    out.close()
elif sys.argv[1] == "decrypt":
    pub = RSA_load_pub(sys.argv[2])
    pri = RSA_load_key()
    enc = open("enc", "rb")
    d = hybrid_decrypt(enc.read(), pub, pri)
    enc.close()
    out = open("dec", "wb")
    out.write(d)
    out.close()
