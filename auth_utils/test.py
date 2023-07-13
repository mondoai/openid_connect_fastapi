from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from base64 import b64encode, b64decode 
import hashlib
from pydantic import BaseModel



class Demo(BaseModel):
    name: str
    lastname: str




if __name__ == '__main__':


    ademo = Demo(name='ali', lastname='ismael')

    print(**ademo)

    # access_key = 'some strong access key  123456789012345678901234567890'
    # hmac_key = 'some hmac string 123456789012345678901234567890'

    # key_bytes = bytes(hashlib.sha256(access_key.encode('utf-8')).digest())
    # cipher = AES.new(key_bytes, AES.MODE_CBC, 0)

    # message = 'hello world ...'
    # padded_data = pad(message.encode('utf-8'), cipher.block_size)

    # encrypted_message = cipher.encrypt(padded_data)

    # print(f'hello world, {cipher.block_size=}, {encrypted_message=}')