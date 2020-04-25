# -*- coding: utf-8 -*-


import rsa
import math
import pytest


def testExtendedEuclideanAlgorithm():
    eea = rsa.ExtendedEuclideanAlgorithm(180, 150)
    assert eea.calculateGCD() == (30, 1, -1)
    eea.setXY(13, 10)
    assert eea.calculateGCD() == (1, -3, 4)
    eea.setXY(31, 7)
    assert eea.calculateGCD() == (1, -2, 9)
    eea.setXY(65536, 256)
    assert eea.calculateGCD() == (256, 0, 1)
    
    
def testPrimeNumber():
	pn = rsa.PrimeNumber(10)
	assert pn.convertToDecimal() == 1023
	pn[0] = 0
	assert pn.convertToDecimal() == 511 


def testTestMillerRabin():
	tmr = rsa.TestMillerRabin()
	assert tmr.millerRabin(997, 100) ==  True
	assert tmr.millerRabin(9973, 100) ==  True
	assert tmr.millerRabin(7695, 100) ==  False
	assert tmr.millerRabin(2004757, 100) ==  True
	assert tmr.millerRabin(2004741, 100) == False


def checkIsPrimeNumber(numberForCheck):
	for i in range(2, int(math.sqrt(numberForCheck))):
		if numberForCheck % i == 0:
			return False
	return True
	
	
def testGeneratorOfPrimeNumbers():
	gopn = rsa.GeneratorOfPrimeNumbers(10, 100)
	assert checkIsPrimeNumber(gopn.newPrimeNumber()) == True
	for i in range(20, 41, 10):
		gopn.setKT(i, 100)
		assert checkIsPrimeNumber(gopn.newPrimeNumber()) == True
		
		
def testKeys():
	keys = rsa.Keys()
	keys.genNewPair()
	keys.writeKeys("public.key", "private.key")
	filePublicKey = open("public.key", 'r')
	publicKey = []
	for line in filePublicKey:
		publicKey.append(int(line))
	filePublicKey.close()
	filePrivateKey = open("private.key", 'r')
	privateKey = []
	for line in filePrivateKey:
		privateKey.append(int(line))
	filePrivateKey.close()
	assert publicKey[1] == privateKey[1] * privateKey[2]
	assert ((privateKey[0] * publicKey[0] - 1) % ((privateKey[1] - 1) * (privateKey[2] - 1))) == 0


def testRSA():
	testRSA = rsa.RSA()
	valuesForTesting = [u"123\n456\n78\n90", u"цйяч\n", u"qw\nert\ny", u"ñóçá\né", u"@#\n$%^",
						u"12#$fg\nйёяñ", u"࠹\n࠹", u"𝄞ñ𠈭𝄞й𝄞ad12!", u"𠷤𠷤𠷤𠷤"]
	for i in valuesForTesting:
		fileWithTextToEncrypt = open("fileWithTextToEncrypt", "w", encoding = 'utf-8')
		fileWithTextToEncrypt.write(i)
		fileWithTextToEncrypt.close()
		fileWithEncryptedText = open("fileWithEncryptedText", "w", encoding = 'utf-8')
		fileWithEncryptedText.close()
		fileWithDecryptedText = open("fileWithDecryptedText", "w", encoding = 'utf-8')
		fileWithDecryptedText.close()
		testRSA.encrypt("fileWithTextToEncrypt", "fileWithEncryptedText", "public.key")
		testRSA.decrypt("fileWithDecryptedText", "fileWithEncryptedText", "private.key")
		fileWithTextToEncrypt = open("fileWithTextToEncrypt", "r", encoding = 'utf-8')
		source = ""
		for line in fileWithTextToEncrypt:
			source = source + line
		fileWithTextToEncrypt.close()
		fileWithDecryptedText = open("fileWithDecryptedText", "r", encoding = 'utf-8')
		target = ""
		for line in fileWithDecryptedText:
			target = target + line
		fileWithDecryptedText.close()
		assert source == target
