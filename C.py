import socket
import sys
import time
from FileContent_Manager import FileContentManager
from encryption_algortihms_implementations import *
from utils import *

q_blocks_until_regenerate = 65
KM_IP = "127.0.0.1"
KM_PORT = 1000

B_IP = "127.0.0.1"
B_PORT = 1002

C_IP = "127.0.0.1"
C_PORT = 1003
KC = b'y\x95\x97\xce\xc2@\xad\x9e\xe6B\xc0\x9b$&\x85D'

sock_client_C = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock_client_C.connect((B_IP, B_PORT))
mode_wanted = sock_client_C.recv(100)
print('\n')
print('-'*30)
print("[ClientC] ClientA wants mode:", mode_wanted)

def send_me_K2():
	"""
		Functie care face un request catre nodul M si ii cere cheia K2
		:return: returneaza cheia K2 decriptata cu KC
	"""
	sock_key_manager = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock_key_manager.connect((KM_IP, KM_PORT))
	sock_key_manager.send(b"Send me K2")
	encrypted_K2_received_from_KM = sock_key_manager.recv(100)
	K2 = decrypt_encryption_key_AES(encrypted_K2_received_from_KM, KC)
	print('\n')
	print('-'*30)
	print("[ClientC] I have received K2:", K2)
	sock_key_manager.close()
	return K2

K2 = send_me_K2()

sock_client_C.send(b'I am ready')

number_of_blocks = int(sock_client_C.recv(8).decode('utf-8'))

print('\n')
print('-'*30)
print("[ClientC] There were", number_of_blocks, "blocks sent from B to C")
print('-' * 20)

iv = b'\x7f\x05\xd8H\x15\xb0[\x86{f\xf9\xc3\xb6\xf1\x9fF'

encrypted_blocks = list()
decrypted_blocks = list()

def decryption(encrypted_blocks, key, iv, mode_wanted):
	"""
		:param encrypted_blocks: lista de blocuri encriptate
		:param key: cheia cu care se doreste sa se faca decriptarea
		:param iv: vectorul de initializare
		:param mode_wanted: OFB | CFB | CBC 
		:return: blocurile decriptate
	"""
	if mode_wanted == b"CBC":
		decrypted_blocks = decryption_CBC(encrypted_blocks, key, iv)
	elif mode_wanted == b"CFB":
	    decrypted_blocks = decryption_CFB(encrypted_blocks, key, iv)
	elif mode_wanted == b"OFB":
	    decrypted_blocks = decryption_OFB(encrypted_blocks, key, iv)
	return decrypted_blocks

final = ''

for i in range(0, number_of_blocks):
	
	encrypted_block = sock_client_C.recv(16)
	print("I received the encrypted block: ", encrypted_block)
	print("The length of the current block is: ", len(encrypted_block))
	print('-' * 20)
	encrypted_blocks.append(encrypted_block)
	
	if i != 0 and (i + 1) % q_blocks_until_regenerate == 0:
		# cazul in care trebuie updatat K2 cu noua valoare regenerata de M
		
		K2 = send_me_K2()
		sock_client_C.send(b'I am ready. I have received the new key.')
		print("[ClientC] The new key K2 = ", K2)
		decrypted_blocks = decryption(encrypted_blocks, K2, iv, mode_wanted)

		for block in decrypted_blocks:
			print('-' * 30)
			print("The decryption for the block is:", block)
		
		# final va fi o concatenare de plaintexturi obtinute din decriptarile blocurilor de cate 
		# q_blocks_until_regenerate plus plaintextul format din restul de decriptari din ultimul bloc
		# care este posibil sa contina un numar mai mic de q_blocks_until_regenerate
		
		final += original_plaintext(decrypted_blocks)
		encrypted_blocks = list()

if number_of_blocks < q_blocks_until_regenerate or number_of_blocks % q_blocks_until_regenerate != 0: 
	decrypted_blocks = decryption(encrypted_blocks, K2, iv, mode_wanted)

for block in decrypted_blocks:
	print('-' * 30)
	print("The decryption for the block is:", block)

final += original_plaintext(decrypted_blocks)

print('\n')
print("="*30)
print("This was the original plaintext received from A:")
print(final)

sock_client_C.close()