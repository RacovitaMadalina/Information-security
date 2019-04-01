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
KA = b'\xf2y@\xa0M\x0f\x9a\xbfCoc\xda2#J\xe9'

try:
    mode = sys.argv[1].upper() # CBC, CFB, OFB 
    if mode != "OFB" and mode != "CBC" and mode != "CFB":
        print("Incorrect mode")
        raise Exception
    chosen_mode = bytes(sys.argv[1].encode("UTF-8"))

    # calea absoluta catre fisierul pe care A vrea sa il cripteze
    file_to_encrypt = sys.argv[2]
except Exception as e:
    print("Unexpected error. First arg should be the chosen encryption mode : CBC, CFB, OFB and the second arg should be the absolute path to the file A wants to encrypt")
    exit(-1)


sock_client_A = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock_client_A.bind((A_IP, A_PORT))
sock_client_A.listen(5)
print('\n')
print('-'*30)
print("Waiting for B to connect...")
sock_client_A.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 5)
(connection_B, address) = sock_client_A.accept()
connection_B.send(chosen_mode)

def send_me_k1():
    """
        Functie care face un request catre nodul M si ii cere cheia K2
        :return: returneaza cheia K2 decriptata cu KC
    """
    sock_key_manager = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_key_manager.connect((KM_IP, KM_PORT))
    K1 = send_me_k1_without_socket_initialisation(sock_key_manager)
    return K1

def send_me_k1_without_socket_initialisation(sock_key_manager):
    sock_key_manager.send(b"Send me K1")
    encrypted_K1_received_from_KM = sock_key_manager.recv(100)

    K1 = decrypt_encryption_key_AES(encrypted_K1_received_from_KM, KA)
    print('\n')
    print('-'*30)
    print("[ClientA] I have received K1:", K1)
    sock_key_manager.close()
    return K1

def encrypted_messages_for_B_return(fileContent, key, pack_no):
    plaintexts = list()
    if (pack_no * q_blocks_until_regenerate) < len(fileContent):
        for i in range((pack_no-1)*q_blocks_until_regenerate, pack_no*q_blocks_until_regenerate):
            plaintexts.append(fileContent[i])
    else:
        for i in range((pack_no-1)*q_blocks_until_regenerate, len(fileContent)):
            plaintexts.append(fileContent[i])
    encrypted_messages_for_B = encrypt_message(plaintexts, key, chosen_mode)
    return encrypted_messages_for_B

K1 = send_me_k1()
confirmation_message = connection_B.recv(100).decode("UTF-8")
print('\n')
print('-'*30)
print("[ClientA] Confirmation message from B:", confirmation_message)

if confirmation_message == "I am ready":
    FCM = FileContentManager(file_to_encrypt, K1)
    # FCM.print_file_content()
    encrypted_messages_for_B = encrypt_message(FCM.fileContent, K1, chosen_mode)
    connection_B.send(bytes(str(len(encrypted_messages_for_B)).encode("UTF-8")))
    if len(encrypted_messages_for_B) <= q_blocks_until_regenerate:
        for encrypted_message in encrypted_messages_for_B:
            time.sleep(0.05)
            connection_B.send(encrypted_message)
    else:
        what_to_encrypt = list()
        fileContent = FCM.fileContent
        
        # indexul curent al pachetelor formate din cate q_blocks_until_regenerate
        package_number = 1 
        encrypted_messages_for_B = encrypted_messages_for_B_return(fileContent, K1, package_number)

        for index in range(0, len(fileContent)):
            what_to_encrypt.append(fileContent[index])
            time.sleep(0.05)
            connection_B.send(encrypted_messages_for_B[index % q_blocks_until_regenerate])
            
            if index !=0 and (index + 1) % q_blocks_until_regenerate == 0:
                sock_key_manager = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock_key_manager.connect((KM_IP, KM_PORT))
                sock_key_manager.send(b"Regenerate keys")
                confirmation_message = sock_key_manager.recv(100)
                
                if b"Regeneration finished" == confirmation_message:
                    sock_key_manager.close()
                    K1 = send_me_k1()
                    print("[ClientA] The new key K1 is:", K1)
                    package_number +=1
                    encrypted_messages_for_B = encrypted_messages_for_B_return(fileContent, K1, package_number)
                    connection_B.send(b'Ready')
                
                confirmation_message = connection_B.recv(100).decode("UTF-8")
                print('\n')
                print('-'*30)
                print("[ClientA] Confirmation message from B:", confirmation_message)
    print('\n')
    print('-'*30)
    print("[ClientA] Crypted blocks have been sent to B")
else:
    print("Something went wrong")

sock_client_A.close()
