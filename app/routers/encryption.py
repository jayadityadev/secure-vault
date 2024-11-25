from fastapi import APIRouter, HTTPException, UploadFile
import base64
import numpy as np

router = APIRouter()

def fourier_encrypt(data: bytes, encryption_key: int):
    numeric_data = np.array([ord(char) for char in data.decode()], dtype=np.float64)
    frequency_components = np.fft.fft(numeric_data)
    encrypted_frequencies = frequency_components * encryption_key
    return encrypted_frequencies

def fourier_decrypt(encrypted_frequencies, encryption_key: int):
    decrypted_frequencies = encrypted_frequencies / encryption_key
    numeric_data = np.fft.ifft(decrypted_frequencies)
    return ''.join(chr(int(round(value.real))) for value in numeric_data)

@router.post("/encrypt")
async def encrypt(file: UploadFile, encryption_key: int):
    contents = await file.read()
    encrypted = fourier_encrypt(contents, encryption_key)
    return {"encrypted_data": encrypted.tolist()}

@router.post("/decrypt")
async def decrypt(data: list, encryption_key: int):
    encrypted_array = np.array(data, dtype=np.complex128)
    decrypted = fourier_decrypt(encrypted_array, encryption_key)
    return {"decrypted_data": decrypted}
