import socket
import sys
import time
from FileContent_Manager import FileContentManager
from utils import *
from encryption_algortihms_implementations import *

q_blocks_until_regenerate = 65
KM_IP = "127.0.0.1"
KM_PORT = 1000

A_IP = "127.0.0.1"
A_PORT = 1001

B_IP = "127.0.0.1"
B_PORT = 1002

C_IP = "127.0.0.1"
C_PORT = 1003
KB = b'\xf4$\xd9\xe3 %\x15\xf0\xc8*\x08\xde\xb2\xa0\xbb8'

sock_client_A = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock_client_A.connect((A_IP, A_PORT))
mode_wanted = sock_client_A.recv(100)
print('\n')
print('-'*30)
print("[ClientB] ClientA wants mode:", mode_wanted.decode("UTF-8"))

time.sleep(2)

sock_client_B = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock_client_B.bind((B_IP, B_PORT))
sock_client_B.listen(5)
print('\n')
print('-'*30)
print("Waiting for C to connect...")
sock_client_B.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 5)
(connection_C, address) = sock_client_B.accept()
connection_C.send(mode_wanted)


def send_me_k1_k2():
	"""
		Functie care face un request catre nodul M si ii cere cheile K1,k2
		:return: tuplu format din K1 si K2 decriptate cu KC
	"""
	sock_key_manager = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock_key_manager.connect((KM_IP, KM_PORT))
	sock_key_manager.send(b'Send me K1, K2')
	encrypted_K1_received_from_KM, encrypted_K2_received_from_KM = sock_key_manager.recv(2048).split(b'//')
	print(encrypted_K1_received_from_KM)
	print(encrypted_K2_received_from_KM)
	K1 = decrypt_encryption_key_AES(encrypted_K1_received_from_KM, KB)
	K2 = decrypt_encryption_key_AES(encrypted_K2_received_from_KM, KB)
	print('\n')
	print('-'*30)
	print("[ClientB] I have received K1 and K2:")
	print("K1 = ", K1)
	print("K2 = ", K2)
	sock_key_manager.close()
	return (K1, K2)

tuple_keys = send_me_k1_k2()
K1 = tuple_keys[0]
K2 = tuple_keys[1]

confirmation_message = connection_C.recv(100).decode("UTF-8")
print('\n')
print('-'*30)
print("[ClientB]Confirmation message from C:", confirmation_message)
sock_client_A.send(b"I am ready")

number_of_blocks = int(sock_client_A.recv(8).decode('utf-8'))
print('\n')
print('-'*30)
print("[ClientB] There were", number_of_blocks, "blocks sent from A to B")
print('-' * 20)

encrypted_blocks = list()
iv = b'\x7f\x05\xd8H\x15\xb0[\x86{f\xf9\xc3\xb6\xf1\x9fF'

connection_C.send(bytes(str(number_of_blocks).encode("UTF-8")))

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

final_plaintext = ''

for i in range(0, number_of_blocks):
	encrypted_block = sock_client_A.recv(16)
	print("I have received the encrypted_block: ", encrypted_block)
	print("The length of the current block is: ", len(encrypted_block))
	print('-' * 20)
	encrypted_blocks.append(encrypted_block)
	if i != 0 and (i + 1) % q_blocks_until_regenerate == 0:
		confirmation_message = sock_client_A.recv(10)
		if confirmation_message == b"Ready":
			decrypted_blocks = decryption(encrypted_blocks, K1, iv, mode_wanted)

			tuple_keys = send_me_k1_k2()
			K1 = tuple_keys[0]
			K2 = tuple_keys[1]

			for block in decrypted_blocks:
				print('-' * 30)
				print("The decryption for the block is:", block)

			# odata ce encryted blocks a ajuns la dimensiunea de q_blocks_until_regenerate trimitem pachetul de 
			# q blocuri catre C pentru a-si primi si el cheile de decriptare
			encrypted_messages_for_C = encrypt_message(decrypted_blocks, K2, mode_wanted)
			for block in encrypted_messages_for_C:
			    time.sleep(0.05)
			    connection_C.send(block)

			final_plaintext += original_plaintext(decrypted_blocks)
			confirmation_message = connection_C.recv(100).decode("UTF-8")
			print('\n')
			print('-'*30)
			print("[ClientB]Confirmation message from C:", confirmation_message)
			sock_client_A.send(b"I am ready. I have received the new keys.")
			print("[ClientB] The new keys K1 and K2:")
			print("K1 = ", K1)
			print("K2 = ", K2)
			encrypted_blocks = list()

if (number_of_blocks < q_blocks_until_regenerate) or (number_of_blocks % q_blocks_until_regenerate != 0): 
	decrypted_blocks = decryption(encrypted_blocks, K1, iv, mode_wanted)

	for block in decrypted_blocks:
		print('-' * 30)
		print("The decryption for the block is:", block)
		
	final_plaintext += original_plaintext(decrypted_blocks)
	encrypted_messages_for_C = encrypt_message(decrypted_blocks, K2, mode_wanted)
	
	for block in encrypted_messages_for_C:
	    time.sleep(0.05)
	    connection_C.send(block)

print('\n')
print("="*30)
print("This was the original plaintext received from A:")
print(final_plaintext)

print('\n')
print('-'*30)
print("[ClientB] Crypted blocks have been sent to C")

sock_client_A.close()
sock_client_B.close()

