# /usr/bin/python
# coding:utf-8
# author : Victor Chen
# 2018/5/3

from Crypto.Cipher import DES
from Crypto.Cipher import AES
from Crypto.Random import random

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

from Crypto.Hash import MD5
from Crypto.Signature import PKCS1_v1_5 as sig_pkc

from Module_Str import PADDING as PD

import cipherUtil as cu

# import package for testing
import os
import time
import Communicate_Str as COMSTR

"""
	注意三个部分，即秘钥、密文、签名
	对文件的传输：
	1、每个包都包括这三个部分，每次的秘钥设定为不同
	2、文件传输稍有不同，最后的文件才需要填充处理
"""

"""
	生成随机秘钥
"""
def RandomKey(n):
	return str(random.getrandbits(n))

# AES 加密解密函数组
# 暂时使用AES128位秘钥加密算法加密
def initialAES(key):
	print key
	if (len(key) < 16):
		raise Exception("The length of keys is not enough")
	return AES.new(key[0:16])

# 设计不需要填充位数的加密和需要最后填充的加密过程
def aesEnStandard(data, a):
	return a.encrypt(data)

# 加密时先填充再加密
def aesEnFill(data, a, chunckSize = 2048):
	# 右端填充PD至chunckSize大小
	return a.encrypt(data.ljust(chunckSize, PD))

# 解密时先解密再去填充
def aesDeFill(ciphertext, a):
	# 去右端填充PD
	return a.decrypt(ciphertext).rstrip(PD)

def aesDeStandard(ciphertext, a):
	return a.decrypt(ciphertext)

# DES 加密解密函数组
def initialDES(key):
	if (len(key) < 8):
		raise Exception("The length of keys is not enough")
	return DES.new(key[0:8])

# 设计不需要填充位数的加密和需要最后填充的加密过程
# 实际desStandard可以使用desEnFill替代，但是解密desDeStandard不能用desDeFill替代
def desEnStandard(data, d):
	return d.encrypt(data)

def desEnFill(data, d, chunckSize = 2048):
	# 仍然填充PD至chunckSize大小
	return d.encrypt(data.ljust(chunckSize, PD))

def desDeFill(ciphertext, d, chunckSize = 2048):
	# 去填充
	return d.decrypt(ciphertext).rstrip(PD)

def desDeStandard(ciphertext, d):
	return d.decrypt(ciphertext)

"""
	由于文件加密必须分组加密，还要考虑文件读取，如何分离文件读取和加密、解密过程
	采用先读，读完所有数据再加密，写解密，再全部写入

	缺点：
		当文件特别大的时候，一次性的str会超过内存

		效率太低了...20MB的文件大概需要1min+ 主要时间仍是消耗在加密解密过程中，str载入和写入时间很短

		python本身对string长度无强制性限制。使用过程中主要需要考虑电脑性能和程序效率

	如何设计可以使传输在DES和AES中切换？
"""
def FileEncrypt(key, plaintext, chunckSize = 2048):
	a = initialAES(key)
	ciphertext = ''
	point = 0
	length = len(plaintext)
	while True:
		# 处理最后的字节需要加填充
		if (length - point) <= chunckSize:
			group = plaintext[point: ]
			ciphertext += aesEnFill(group, a, chunckSize)
			break
		# 普通情况下不需要去填充
		else:
			group = plaintext[point: point+chunckSize]
			ciphertext += aesEnStandard(group, a)
		point += chunckSize
	return ciphertext

def FileDecrypt(key, ciphertext, chunckSize = 2048):
	a = initialAES(key)
	plaintext = ''
	point = 0
	length = len(ciphertext)
	while True:
		# 处理最后的字节需要去填充，一般情况下等于chunckSize
		if (length - point) <= chunckSize:
			group = ciphertext[point: ]
			plaintext += aesDeFill(group, a)
			break
		# 普通情况下不需要去填充
		else:
			group = ciphertext[point: point+chunckSize]
			plaintext += aesDeStandard(group, a)
		point += chunckSize

	return plaintext

# RSA 加密
def rsaEn(pem_path, plaintext):
	rsa_ems = None
	with open(pem_path) as f:
		key = f.read()
		rsaKey = RSA.importKey(key)
		rsa_en = PKCS1_v1_5.new(rsaKey)
		rsa_ems = rsa_en.encrypt(plaintext)
	return rsa_ems

# RSA 解密，  decrypt的第二个参数有待商榷
def rsaDe(pem_path, ciphertext):
	rsa_dms = None
	with open(pem_path) as f:
		key = f.read()
		rsaKey = RSA.importKey(key)
		rsa_de = PKCS1_v1_5.new(rsaKey)
		rsa_dms = rsa_de.decrypt(ciphertext,0)
	return rsa_dms

# 签名
def Signature(privateKey_path, plaintext):
	signature = None
	hashm = MD5.new(plaintext)
	with open(privateKey_path) as f:
		key = f.read()
		rsaKey = RSA.importKey(key)
		signer = sig_pkc.new(rsaKey)
		signature = signer.sign(hashm)
#	print hashm.hexdigest()
	return signature

# 检查签名
def VerifySignature(public_key_path, plaintext, signature):
	isVerified = False
	hashm = MD5.new(plaintext)
	with open(public_key_path) as f:
		key = f.read()
		rsaKey = RSA.importKey(key)
		unsigner = sig_pkc.new(rsaKey)
		if unsigner.verify(hashm, signature):
			isVerified =True
#	print hashm.hexdigest()
	return isVerified


# 时间点记录，测试使用
def clock():
	timeArray = time.localtime(time.time())
	print time.strftime("%H:%M:%S", timeArray)



if __name__ == '__main__':
	os.chdir('E:/Workspace/pythonCode/EncrytedTransfer/testFile')
	sourceFile = 'tupian.png'
	destinFile = 'copy'
	destinFile += sourceFile[ sourceFile.rindex('.') : ]

	print 'read'
	clock()
	# 文件读取过程

	# 原文
	rdata = ''
	chunckSize = 4096*4
	with open(sourceFile,'rb+') as fr:
			rdata = fr.read()

	key = RandomKey(64)
	print 'key : %s' % (key)
	clock()
	# 加密过程
	Todata = FileEncrypt(key, rdata, chunckSize)
	print 'SYSMETRIC COMPLETED' 
	clock()
	cipherkey = rsaEn(COMSTR.THERE_PUBLIC, key)
	signature = Signature(COMSTR.HERE_PRIVATE, rdata)

	# Transfer data 
	print 'Transfer'
	clock()

	key = rsaDe(COMSTR.THERE_PRIVATE, cipherkey)
	print key

	# 解密过程
	# 解密得到的密文
	Getdata = FileDecrypt(key, Todata, chunckSize)

	print len(rdata),' ?= ',len(Getdata)

	print 'write'
	clock()

	with open(destinFile,'wb+') as fw:
		fw.write(Getdata) 
		fw.flush()

	print 'SYSM finish'
	clock()

	print VerifySignature(COMSTR.HERE_PUBLIC, Getdata, signature)
	clock()

	fr.close()
	fw.close()

