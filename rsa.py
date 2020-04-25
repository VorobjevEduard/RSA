import random
import math


class ExtendedEuclideanAlgorithm:
    '''Расширенный алгоритм Евклида используется 
		для вычисления закрытой экспоненты'''
    
    def __init__(self, x, y):
        self.setXY(x, y)
    
    def __isNotNaturalNumber__(self, numberForCheck):
        if not float(numberForCheck).is_integer() or numberForCheck <= 0:
            return True
        else:
            return False
    
    def setXY(self, x, y):
        '''Входные параметры должны быть натуральные, x >= y'''
        if x < y or self.__isNotNaturalNumber__(x) or self.__isNotNaturalNumber__(y):
            print("Неверные входные данные на этапе вычисления закрытой экспоненты")
            exit()
        self.x = x
        self.y = y
    
    
    def calculateGCD(self):
        '''Возвращает НОД чисел x, y
            и числа a, b такие, что a * x + b * y = НОД(x, y)'''
        a1, a2, b1, b2 = 0, 1, 1, 0
        while self.y != 0:
            q = self.x // self.y
            r = self.x - q * self.y
            a = a2 - q * a1
            b = b2 - q * b1
            self.x = self.y
            self.y = r
            a2 = a1
            a1 = a
            b2 = b1
            b1 = b
        m = self.x
        a = a2
        b = b2
        return m, a, b


class PrimeNumber:
    '''Потенциально простое число в двоичном представлении'''
    
    
    def __init__(self, k):
        '''k - размер в битах числа'''
        self.primeNumber = [1] * k
    
    
    def __setitem__(self, key, value):
        self.primeNumber[key] = value
        
        
    def convertToDecimal(self):
        stringPrimeNumber = ""
        for i in self.primeNumber:
            stringPrimeNumber = stringPrimeNumber + str(i)
        return int(stringPrimeNumber, 2)                    


class TestMillerRabin:
    '''Далает предположение с определенной 
        вероятностью о простоте числа'''
    
    
    def __divOnTwo(self, n):
        '''Находит s, t такие, что n = (2**s) * t'''
        s = 0
        while (n % 2) == 0:
            s = s + 1
            n = n // 2
        return s, n
 
 
    def millerRabin(self, n, numberOfIteration): 
        s, t = self.__divOnTwo(n - 1)
        for i in range(numberOfIteration):
            a = random.randint(2, n - 2)
            x = pow(a, t, n)
            if x == 1 or x == (n - 1):
                continue
            flagNewItaration = False
            for j in range(s - 1):
                x = pow(x, 2, n)
                if x == 1:
                    return False # составное
                if x == (n - 1):
                    flagNewItaration = True
            if flagNewItaration:
                continue
            return False
        return True
            

class GeneratorOfPrimeNumbers:
    '''Генератор простых чисел используется
        для генерации параметров'''
    
    
    def __init__(self, k, t = 100):
        self.setKT(k, t)
    
    
    def setKT(self, k, t):
        '''k - разрядность генерируемого простого числа,
            t - параметр для оценки того, что k простое'''
        if t < 1:
            print("Параметр t задан неверно")
            exit()
        self.k = k
        self.t = t
    
        
    def newPrimeNumber(self):
        '''Возвращает число p, простое с вероятностью 1 - (1 / 4 ** t)'''
        while True:
            p = PrimeNumber(self.k)
            for i in range(1, self.k - 2):
                p[i] = random.randint(0, 1)
            flagNewIteration = False
            for i in [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
                if (p.convertToDecimal() % i) == 0:
                    flagNewIteration = True
                    break
            if flagNewIteration:
                continue
            tmr = TestMillerRabin()
            if tmr.millerRabin(p.convertToDecimal(), self.t):
                return p.convertToDecimal() 
            else:
                continue


class Keys:
	'''Публичный ключ частично по формату PKCS8,
		приватный ключ частично по формату PKCS12'''
	
	__publicKey = []
	__privateKey = []
	
	def genNewPair(self):
		while True:
			size = 64 # размер в битах
			gopn = GeneratorOfPrimeNumbers(size)
			p, q = gopn.newPrimeNumber(), gopn.newPrimeNumber()
			n = p * q
			publicExponent = gopn.newPrimeNumber()
			eea = ExtendedEuclideanAlgorithm((p - 1) * (q - 1), publicExponent)
			privateExponent = eea.calculateGCD()[2]
			if privateExponent < 0 or publicExponent < 0:
				continue
			exponent1 = privateExponent % (p - 1)
			exponent2 = privateExponent % (q - 1)
			coefficient = 0
			if (q > p):
				eea.setXY(q, p)
				coefficient = eea.calculateGCD()[1]
			else:
				eea.setXY(p, q)
				coefficient = eea.calculateGCD()[2]
			self.__publicKey = [publicExponent, n]
			self.__privateKey = [privateExponent, p, q, \
					exponent1, exponent2, coefficient]
			return
		
	
	def writeKeys(self, filenamePublicKey, filenamePrivateKey):
		filePublicKey = open(filenamePublicKey, 'w')
		for i in self.__publicKey:
			filePublicKey.write(str(i) + '\n')
		filePublicKey.close()
		filePrivateKey = open(filenamePrivateKey, 'w')
		for i in self.__privateKey:
			filePrivateKey.write(str(i) + '\n')
		filePrivateKey.close()


class RSA:
	'''Производит зашифрование и расшифрование 
		текста поблочно по алгоритму RSA'''
	
	
	__blockSize = 32	# размер блока в битах
	__text = ""
	__textByBlocks = []
	
	
	def __completeToBlock(self):
		self.__text = self.__text + \
		'0' * (self.__blockSize - len(self.__text) % self.__blockSize)
		
		
	def __divOnBlocks(self):
		for i in range(0, len(self.__text), self.__blockSize):
			self.__textByBlocks.append(self.__text[i: i + self.__blockSize])	
	
	
	def encrypt(self, filenameOpentext, filenameCiphertext, filenamePublicKey):
		self.__text = ""
		self.__textByBlocks = []
		fileOpentext = open(filenameOpentext, 'r', encoding = 'utf-8')
		fileCiphertext = open(filenameCiphertext, 'w', encoding = 'utf-8')
		filePublicKey = open(filenamePublicKey, 'r', encoding = 'utf-8')
		for line in fileOpentext:
			line = line.encode("utf-8")
			for i in line:
				symbolCode = bin(i)[2:]
				symbolCode = "0" * (8 - len(symbolCode)) + symbolCode
				self.__text = self.__text + symbolCode
		self.__completeToBlock()
		self.__divOnBlocks()
		publicKey = []
		for i in filePublicKey:
			publicKey.append(i)
		for i in self.__textByBlocks:
			fileCiphertext.write(str(pow(int(i, 2), int(publicKey[0]), int(publicKey[1]))) + "\n")
		fileOpentext.close()
		fileCiphertext.close()
		filePublicKey.close()
		
		
	def decrypt(self, filenameOpentext, filenameCiphertext, filenamePrivateKey):
		self.__text = ""
		fileOpentext = open(filenameOpentext, 'w', encoding = 'utf-8')
		fileCiphertext = open(filenameCiphertext, 'r', encoding = 'utf-8')
		filePrivateKey = open(filenamePrivateKey, 'r', encoding = 'utf-8')
		privateKey = []
		for i in filePrivateKey:
			privateKey.append(i)
		for line in fileCiphertext:
			decryptedBlock = bin(int(pow(int(line), int(privateKey[0]),\
				int(privateKey[1]) * int(privateKey[2]))))[2:]
			if (len(decryptedBlock) != self.__blockSize):
				decryptedBlock = "0" * (self.__blockSize - len(decryptedBlock)) + decryptedBlock
			self.__text = self.__text + decryptedBlock
		for i in range(0, len(self.__text), 8):
			if self.__text[i] == "0":
				if self.__text[i : i + 8] != "00000000":
					fileOpentext.write(chr(int(self.__text[i: i + 8], 2)))
			elif self.__text[i : i + 3] == "110":
				firstByte = self.__text[i : i + 8]
				firstByte = hex(int(firstByte, 2))[2:]
				i = i + 8
				secondByte = self.__text[i : i + 8]
				secondByte = hex(int(secondByte, 2))[2:]
				allBytes = bytes.fromhex(firstByte + secondByte)
				if allBytes != b'\x00\x00':
					fileOpentext.write(allBytes.decode("utf-8"))
			elif self.__text[i : i + 4] == "1110":
				firstByte = self.__text[i : i + 8]
				firstByte = hex(int(firstByte, 2))[2:]
				i = i + 8
				secondByte = self.__text[i : i + 8]
				secondByte = hex(int(secondByte, 2))[2:]
				i = i + 8
				thirdByte = self.__text[i : i + 8]
				thirdByte = hex(int(thirdByte, 2))[2:]
				allBytes = bytes.fromhex(firstByte + secondByte + thirdByte)
				if allBytes != b'\x00\x00\x00':
					fileOpentext.write(allBytes.decode("utf-8"))
			elif self.__text[i : i + 5] == "11110":
				firstByte = self.__text[i : i + 8]
				firstByte = hex(int(firstByte, 2))[2:]
				i = i + 8
				secondByte = self.__text[i : i + 8]
				secondByte = hex(int(secondByte, 2))[2:]
				i = i + 8
				thirdByte = self.__text[i : i + 8]
				thirdByte = hex(int(thirdByte, 2))[2:]
				i = i + 8
				fourthByte = self.__text[i : i + 8]
				fourthByte = hex(int(fourthByte, 2))[2:]
				allBytes = bytes.fromhex(firstByte + secondByte + thirdByte + fourthByte)
				if allBytes != b'\x00\x00\x00\x00':
					fileOpentext.write(allBytes.decode("utf-8"))
		fileOpentext.close()
		fileCiphertext.close()
		filePrivateKey.close()


if __name__ == "__main__":
    while True:
        print("Выберете действие:")
        print("1. сгенерировать новую пару ключей;")
        print("2. зашифровать текст;")
        print("3. расшифровать текст;")
        print("4. выйти из программы.")
        userSelect = int(input())
        if userSelect == 1:
            k = Keys()
            publicKey = str(input("Введите имя файла, в который будет записан открытый ключ: "))
            privateKey = str(input("Введите имя файла, в который будет записан секретный ключ: "))
            k.genNewPair()
            k.writeKeys(publicKey, privateKey)
        elif userSelect == 2:
            publicKey = str(input("Введите имя файла c открытым ключом: "))
            openText = str(input("Введите имя файла с открытым текстом: "))
            encryptedText = str(input("Введите имя файла, куда будет записан зашифрованный текст: "))
            r = RSA()
            r.encrypt(openText, encryptedText, publicKey)
        elif userSelect == 3:
            privateKey = str(input("Введите имя файла c секретным ключом: "))
            openText = str(input("Введите имя файла, куда будет записан расшифрованный текст: "))
            encryptedText = str(input("Введите имя файла с зашифрованным текстом: "))
            r = RSA()
            r.decrypt(openText, encryptedText, privateKey)
        elif userSelect == 4:
            print("¡Suerte y chao!")
            exit()
        else:
            print("Ошибка выбора действия. Попробуйте еще раз.")
        print()
