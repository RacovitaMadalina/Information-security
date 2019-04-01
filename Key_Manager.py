from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class Key_Manager(object):
    def __init__(self, KA, KB, KC, K1, K2):
        """
        :param KA: KA va cripta datele trimise de la M catre A
        :param KB: KB va cripta datele trimise de la M catre B
        :param KC: KC va cripta datele trimise de la M catre C
        :param K1: K1 va cripta datele trimise intre A si B
        :param K2: K2 va cripta datele trimise intre B si C
        """
        self.KA = KA
        self.KB = KB
        self.KC = KC
        self.K1 = K1
        self.K2 = K2

    def get_key(self, message: str):
        """
        :param message: spre ex. receiverul A a trimis in pasul anterior mesajul "Send me K1"
        :return: cheia/cheile criptata/criptate cu KA, KB, KC in functie de cine este receiverul
        """
        if "Send me K1" == message:
            return self.encrypt_key_AES(self.K1, self.KA)
        elif "Send me K1, K2" == message:
            encryted_k1 = self.encrypt_key_AES(self.K1, self.KB)
            encryted_k2 = self.encrypt_key_AES(self.K2, self.KB)
            return encryted_k1 + str.encode("//") + encryted_k2
        elif "Send me K2" == message:
            return self.encrypt_key_AES(self.K2, self.KC)
        else:
            raise Exception("Not allowed to receive the requested key/keys or incorrect receiver name")

    def encrypt_key_AES(self, plain_text, key):
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        cipherText = encryptor.update(plain_text) + encryptor.finalize()
        return cipherText



