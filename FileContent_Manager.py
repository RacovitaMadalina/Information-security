class FileContentManager:
    def __init__(self, file_path, key):
        """
        :param file_path: Calea absoluta catre fisierul pe care A vrea sa il cripteze
        :param key: Cheia folosita pentru a cripta continutul fisierului       
        """
        self.file_path = file_path
        self.key = key
        self.fileContent = self.read_file(file_path)

    def read_file(self, file_path) -> list:
        """
        :param file_path: Calea absoluta catre fisierul pe care A vrea sa il cripteze
        :return: o lista de blocuri de 16 biti ale continutului fisierului
        """
        try:
            fileObject = open(file_path, mode="rb")
            fileContent = list()
            while True:
                content = fileObject.read(16)
                if len(content) == 0:
                    break
                fileContent.append(content)
            return fileContent
        except FileNotFoundError:
            print("Wrong file or file path")

    def print_file_content(self):
        print("These are the blocks to be encrypted")
        print('-' * 20)
        for block in self.fileContent:
            print(block)
            print("The length of this block is: ", len(block))
            print('-' * 20)
        