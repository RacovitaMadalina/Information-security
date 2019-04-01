from Key_Manager import Key_Manager
import socket
import sys
import os

IP = "127.0.0.1" # localhost
PORT = 1000 # default port for the key manager

try: 
	# KA, KB, KC chei asociate unui cifru simetric; am ales AES
	KA = b'\xf2y@\xa0M\x0f\x9a\xbfCoc\xda2#J\xe9'
	KB = b'\xf4$\xd9\xe3 %\x15\xf0\xc8*\x08\xde\xb2\xa0\xbb8'
	KC = b'y\x95\x97\xce\xc2@\xad\x9e\xe6B\xc0\x9b$&\x85D'

	# K1, K2 asociate altui cifru simetric; am ales DES
	# or os.urandom(16)
	K1 = b'\x9b\x0f\x19\x7fH"h>UB\x18\xd1\x97\x15\xd7J'
	K2 = b'\x9f\x0c\xe4\xe9>\xf0>\x1fP\xf8*%K\x1e\xbd\xd7'

	q_blocks_until_regenerate = 7
	KM = Key_Manager(KA, KB, KC, K1, K2)
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.bind((IP, PORT))
	sock.listen(5)
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 5)
	print("[Key Manager] Waiting connections at: {ip} : {port}".format(ip=IP, port=PORT))
	while True:
	    (connection, address) = sock.accept()
	    print('\n')
	    print('-'*30)
	    print("Received connection:", address)
	    received_message = connection.recv(16)
	    print("Received message:", received_message)
	    if b"Send me K1" == received_message:
	        print("The client has a request for K1")
	        response = KM.get_key("Send me K1")
	        connection.send(response)
	        print("Sent the key K1 encrypted with KA: ", response)
	    elif b"Send me K1, K2" == received_message:
	        print("The client has a request for K1 and K2")
	        response = KM.get_key("Send me K1, K2")
	        connection.send(response)
	        print("Sent the keys K1 and K2 encrypted with KB: ", response)
	    elif b"Send me K2" == received_message:
	        print("The client has a request for K2")
	        response = KM.get_key("Send me K2")
	        connection.send(response)
	        print("Sent the key K2 encrypted with KC: ", response)
	    elif b"Regenerate keys" == received_message:
	    	print("Reached the number of blocks granted to be sent. KM will regenerate the keys")
	    	K1 = os.urandom(16)
	    	K2 = os.urandom(16)
	    	print("K1 = ", K1)
	    	print("K2 = ", K2)
	    	KM = Key_Manager(KA, KB, KC, K1, K2)
	    	connection.send(b"Regeneration finished")
	    elif b"exit" == received_message:
	        break
	print("Key manager shutting down")

except KeyboardInterrupt as e:
    sock.close()