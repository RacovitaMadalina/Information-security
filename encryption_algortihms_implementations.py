from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from os import urandom

def encrypt_message(file_content: list, key, mode: str) -> list:
    """
	    :param file_content: Continutul fisierului pe care vreau sa il criptez dizivat in blocuri
	    :param key: cheia folosita la criptare
	    :param mode: modul de criptare folosit OFB, CBC, CFB
	    :return: returneaza o lista de blocuri criptate
    """
    print("Encryption mode:", mode)
    # iv = urandom(16) # initialisation vector
    iv = b'\x7f\x05\xd8H\x15\xb0[\x86{f\xf9\xc3\xb6\xf1\x9fF'
    if mode == b"OFB":
        return encryption_OFB(file_content, key, iv)
    elif mode == b"CBC":
        return encryption_CBC(file_content, key, iv)
    elif mode == b"CFB":
        return encryption_CFB(file_content, key, iv)

def xor_between_arrays(s1, s2):
    """
	    :param s1: primul vector de biti
	    :param s2: al doilea vector de biti
	    :return: s1 ^ s1
    """
    final_result = bytes('', encoding="UTF-8")
    for i in range(0, len(s1)):
        xor = s1[i] ^ s2[i]
        current = xor.to_bytes((xor.bit_length() + 7) // 8, byteorder="big")
        if len(current) == 0:
            final_result += b"\x00"
        else:
            final_result += current
    return final_result

def encryption_CBC(file_content, key, iv):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), default_backend())
    encrypted_data = []

    for block in file_content:
        encryptor = cipher.encryptor()

        # cazul in care ultimul bloc nu are dimensiunea de 16 bytes
        if len(block) != 16: 
            padder = padding.ANSIX923(128).padder()
            block = padder.update(block) + padder.finalize()
       
        result = xor_between_arrays(block, iv)
        final = encryptor.update(result) + encryptor.finalize()
        
        # criptotextul curent dupa XOR-ul cu plaintextul 
        # devine vector de initilizare pentru blocul urmator

        iv = final
        encrypted_data.append(final) 
    return encrypted_data

def decryption_CBC(cipher_text, key, iv):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), default_backend())
 
    decrypted_data = []
 	
    for encrypted_block in cipher_text:
        encryptor = cipher.decryptor()
        copy_iv = iv
        iv = encrypted_block
        result = encryptor.update(encrypted_block) + encryptor.finalize()
        final = xor_between_arrays(copy_iv, result)
        decrypted_data.append(final)

    # incercam sa obtinem blocul initial, in cazul in care acesta nu a avut initial 16 bytes
    try:
        unpadder = padding.ANSIX923(128).unpadder()
        decrypted_data[-1] = unpadder.update(decrypted_data[-1]) + unpadder.finalize()
    except Exception as e:
        pass
    return decrypted_data

def encryption_OFB(file_content, key, iv):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), default_backend())
    encrypted_data = []

    for block in file_content:
        encryptor = cipher.encryptor()

 		# cazul in care ultimul bloc nu are dimensiunea de 16 bytes
        if len(block) != 16: 
            padder = padding.ANSIX923(128).padder()
            block = padder.update(block) + padder.finalize()
        result = encryptor.update(iv) + encryptor.finalize()
        # criptotextul curent inainte de XOR-ul cu plaintextul 
        # devine vector de initilizare pentru blocul urmator
        iv = result
        result = xor_between_arrays(block, result)
        encrypted_data.append(result) 
    return encrypted_data


def decryption_OFB(cipher_text, key, iv):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), default_backend())
 
    decrypted_data = []
 
    for encrypted_block in cipher_text:
        encryptor = cipher.encryptor()
        current = encrypted_block
        result = encryptor.update(iv) + encryptor.finalize()
        iv = result
        result = xor_between_arrays(current, result)
        decrypted_data.append(result)

    # incercam sa obtinem blocul initial, in cazul in care acesta nu a avut initial 16 bytes
    try:
        unpadder = padding.ANSIX923(128).unpadder()
        decrypted_data[-1] = unpadder.update(decrypted_data[-1]) + unpadder.finalize()
    except Exception as e:
        pass
    return decrypted_data

def encryption_CFB(file_content, key, iv):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), default_backend())
    encrypted_data = []

    for block in file_content:
        encryptor = cipher.encryptor()

 		# cazul in care ultimul bloc nu are dimensiunea de 16 bytes
        if len(block) != 16: 
            padder = padding.ANSIX923(128).padder()
            block = padder.update(block) + padder.finalize()
        result = encryptor.update(iv) + encryptor.finalize()
        result = xor_between_arrays(block, result)
        # criptotextul curent dupa XOR-ul cu plaintextul 
        # devine vector de initilizare pentru blocul urmator
        iv = result
        encrypted_data.append(result) 
    return encrypted_data


def decryption_CFB(cipher_text, key, iv):
    cipher = Cipher(algorithms.TripleDES(key), modes.ECB(), default_backend())
 
    decrypted_data = []
 
    for encrypted_block in cipher_text:
        encryptor = cipher.encryptor()
        current = encrypted_block
        result = encryptor.update(iv) + encryptor.finalize()
        iv = current
        result = xor_between_arrays(current, result)
        decrypted_data.append(result)

    # incercam sa obtinem blocul initial, in cazul in care acesta nu a avut initial 16 bytes
    try:
        unpadder = padding.ANSIX923(128).unpadder()
        decrypted_data[-1] = unpadder.update(decrypted_data[-1]) + unpadder.finalize()
    except Exception as e:
        pass
    return decrypted_data

def original_plaintext(blocks: list):
	"""
		Functie care returneaza plaintextul initial concatenand toate blocurile decriptate
	"""
	original_plaintext = ''
	for block in blocks:
	    try:
	        original_plaintext += block.decode('UTF-8')
	    except:
	        pass
	return original_plaintext