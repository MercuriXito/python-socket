# /usr/bin/python
# coding:utf-8
# author : Victor Chen
# 2018/4/30

import os
import ConfigParser as cp

FILE_SAVE_PATH = 'E:/Material/UploadFileTest/'


'''

		struct udp数据报格式:
		h 		传送数据报类型
			0:  文件
			1:	普通消息
		h 		该数据报在文件中的位置 
			0： 结尾
			1： 开头
			2： 传送中间数据
		64s		文件名
		L 		偏移量
		128s    秘钥
		128s	签名
		2048s	密文	

'''
PROTOCOL_DEFINE = 'hh64sL128s128s2048s'

HERE_PUBLIC = os.getcwd() + '/master-public.pem'
HERE_PRIVATE = os.getcwd() + '/master-private.pem'
THERE_PUBLIC = os.getcwd() + '/host-public.pem'
THERE_PRIVATE = os.getcwd() + '/host-private.pem'

class ClientConfig(object):
	"""docstring for ClientConfig"""
	def __init__(self):
		super(ClientConfig, self).__init__()
		self.ini = os.getcwd() + '\\client_config.ini'
		self.config = {}
		# 按照ini的结构构建的section和key的键值对
		self.item = {
			'FILEPATH': (
				'DEFAULT_OPEN_FILE_PATH',
			 	'DEFAULT_SAVE_FILE_PATH',
			 	'LOCAL_PUBLIC',
			 	'LOCAL_PRIVATE'
			 	), 
			'NETWORK': (
				'HOST_IP',
				'HOST_PORT'
				),
			'TEST_ARGS': (
				'REMOTE_PUBLIC',
				'REMOTE_PRIVATE'
				)
		}
		self.initial_args()

	def initial_args(self):
		con = cp.ConfigParser()
		con.read(self.ini)
		for key in self.item:
			for value in self.item[key]:
				self.config[value] = con.get(key,value)
		return self.config

	def getconfig(self):
		return self.config

if __name__ == '__main__':
	cc = ClientConfig()
	d = cc.getconfig()
	for key in d:
		print key+':'+d[key]
	print FILE_SAVE_PATH