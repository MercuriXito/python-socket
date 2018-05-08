# /usr/bin/python
# coding:utf-8
# author : Victor Chen
# 2018/4/30

from Tkinter import *
import ttk
import threading
import socket
import struct
import os
import random
import tkFileDialog
import Communicate_Str as COMSTR

import cipherUtil2 as cu

# 重新加载编码为utf-8 
reload(sys)
sys.setdefaultencoding('utf8')

"""
	对通信客户端的设计，主要包含短消息的传送和文件的传送
	使用UDP报文，设计的报文格式为：
		hh64sL128s128s2048s

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


	对客户端程序添加logging记录日志:

	主要传输和加密过程:
		对该客户端，必须完成发送和接受的两种功能，则需要一个Server类监听和一个Client主类发送消息
		Server:
			处理报文：根据报文的头文件，首先判断是短消息还是文件头数据报对应接受

			考虑多线程：多个客户端同时传送文件????

		Client:
			根据需求发送报文，根据发送消息的类型发送文件




	文件传输三要素的实现：
		发送预备：
		1、读取文件所有二进制流信息，保存在str里
		2、生成随机秘钥，将str加密，得到cipherstr
		3、RSA加密随机秘钥得到cipherkey，将str进行MD5得到hash,再RSA加密得到整个文件的签名

		循环发送
		4、按包长度读取cipherstr，将cipherkey，小段的cipherstr和签名发送

		循环接受：
		5、对包只检查小段的cipherstr，收到所有的包后组装成cipherstr

		接受后处理
		6、RSA得到cipherkey 和 hash值
		7、cipherstr通过解密得到str
		8、验证hash值

		特点：
			1、一次文件使用一把随机的对称秘钥
			2、不适用于大文件传输(最好 < 10 MB)
			3、


		目前COMSTR都是硬编码，包括私钥和秘钥都是提前给出。还需修改默认文件保存路径
			1、公钥交换、一次传输开始前进行公钥交换，
			2、搭建CA认证服务器(顺便做NAT服务器)

		
"""




class Client(Frame):
	def __init__(self,master=None):
		Frame.__init__(self,master)
		self.pack()
		self.createWidgets()
		self.fileD = self.input.get()
		self.ISFILE = False
		self.configObject = COMSTR.ClientConfig()
		self.config = self.configObject.getconfig()

	def createWidgets(self):
		self.PromptFrame = Frame(self)

		self.MessageBox = Text(self.PromptFrame)
		self.MessageBox.bind('<KeyPress>',lambda e: "break")
		self.MessageBox.config(height=10,width=58)
		self.MessageBox.insert(END,'欢迎使用聊天程序啦啦啦~~~~:\n')
		self.MessageBox.pack(side='left')

		self.scrollbar = Scrollbar(self.PromptFrame,command=self.MessageBox.yview)
		self.scrollbar.pack(side='right',fill='y')
		self.MessageBox.config(yscrollcommand=self.scrollbar.set)
		self.PromptFrame.pack()

		self.MessageFrame = Frame(self)

		self.inputLabel = Label(self.MessageFrame,text='信息框:')
		self.inputLabel.pack(side='left')
		self.input = Entry(self.MessageFrame,width=45)
		self.input.bind("<Return>",lambda e: self.send())
		self.input.pack(side='left')

		self.fileButton = Button(self.MessageFrame,text='发送文件',width=10)
		self.fileButton.config( command=self.chooseFile )
		self.fileButton.pack(side='right')

		self.MessageFrame.pack()

		self.sendFrame = Frame(self)
		self.sendFrameLabel1 = Label(self.sendFrame,text='主机:')
		self.sendFrameLabel1.pack(side='left')
		self.sendInput1 = Entry(self.sendFrame)
		self.sendInput1.insert(0,'127.0.0.1')
		self.sendInput1.pack(side='left')
		self.sendFrameLabel2 = Label(self.sendFrame,text='端口:')
		self.sendFrameLabel2.pack(side='left')
		self.sendInput2 = Entry(self.sendFrame)
		self.sendInput2.insert(0,'12000')
		self.sendInput2.pack(side='left')
		self.sendFrame.pack()

		self.buttonFrame = Frame(self)
		self.onLabel = Label(self.buttonFrame,text='上线端口:')
		self.onLabel.pack(side='left')
		self.onInput = Entry(self.buttonFrame,width = 10)
		self.onInput.insert(0,'12000')
		self.onInput.pack(side='left')
		self.onlineButton = Button(self.buttonFrame,width = 10,text = '上线', command = self.logOn)
		self.onlineButton.pack(side = 'left')
		self.clearButton = Button(self.buttonFrame,width = 10,text='清空聊天框',command=self.clearMessage)
		self.clearButton.pack(side = 'left')
		self.sendButton = Button(self.buttonFrame,width = 10, text='发送信息',command = self.send)
		self.sendButton.pack(side='left')
		self.buttonFrame.pack()

	def logOn(self):
		port = int(self.onInput.get())
		self.UDPserver = UDPserver(port,self.MessageBox)
		self.UDPserver.setDaemon(True)
		self.UDPserver.start()

	def send(self):
		host = self.sendInput1.get()
		port = int(self.sendInput2.get())
		getinput = self.input.get()
		if self.ISFILE is True:
			getinput = 'FILE:' + getinput
			self.ISFILE = False
		else:
			self.MessageBox.insert(END,'你说: '+ getinput +'\n')
			getinput = 'MESSAGE:'+ getinput.encode(encoding = 'utf-8')
		self.clientUDP = ClientUDP(host,port,getinput,self.MessageBox)
		self.clientUDP.setDaemon(True)
		self.clientUDP.start()
		print self.clientUDP.isAlive()
		self.input.delete('0','end')

	def chooseFile(self):
		self.fileD = tkFileDialog.askopenfilename(initialdir = 'E:\\Material\\UploadFile')
		self.input.delete(0,len(self.input.get()))
		self.ISFILE = True
		self.input.insert(0,self.fileD)

	def SentFileUDP(self):
#		self.MessageBox.insert(END,'Send file \"%s\" to remote UDP server\n' %(self.fileD))
		udphost = self.UdpInput1.get()
		udpport = int(self.UdpInput2.get())
		self.clientUDP = ClientUDP(udphost,udpport,self.input.get(),self.MessageBox,self.pUbar,self.labelU2)
		self.clientUDP.setDaemon(True)
		self.clientUDP.start()
		print self.clientUDP.isAlive()

	def clearMessage(self):
		self.MessageBox.delete(1.0,'end')
		self.MessageBox.insert(END,'欢迎使用聊天程序啦啦啦~~~~:\n')
		

# 监听线程
class processThread(threading.Thread):
	def __init__(self,udpSocket,Dsavepath,console):
		threading.Thread.__init__(self)
		self.udpSocket = udpSocket
		self.Dsavepath = Dsavepath
		self.console = console
		self.mutex = threading.Lock()
		self.exit = False
		self.datastruct = struct.Struct(COMSTR.PROTOCOL_DEFINE)	

	def writeConsole(self,Message):
		self.console.insert(END,Message)

	def run(self):
		BUFFERSIZE = self.datastruct.size

		tempfilepath = self.Dsavepath + '\\temp'
		tempDirectory = os.path.split(tempfilepath)[0]
		tempk = None

		signature = ''
		key = ''
		databuffer = ''
		chunckSize = 2048 * 8

		while True:
			data,addr = self.udpSocket.recvfrom(BUFFERSIZE)
			if self.exit:
				break
			value = self.datastruct.unpack(data)
			# 还原打包的数据
			ttype = int(value[0])
			tpos = int(value[1])
			fileName = value[2].decode(encoding = 'utf-8')
			deviate = int(value[3])
			cipherkey = value[4]
			signature = value[5]
			cipherdata = value[6]

			if ttype == 1:
				self.udpSocket.sendto('1',addr)
				# 获得秘钥
				key = cu.rsaDe(COMSTR.THERE_PRIVATE, cipherkey)
				# 解密
				data = cu.FileDecrypt(key, cipherdata.rstrip('\x00'), 256)
				# 验证
				if not cu.VerifySignature(COMSTR.HERE_PUBLIC, data, signature):
					raise Exception('VerifySignature failed')
				else:
					print 'OK'
				self.writeConsole('收到 %s / %d 消息:%s\n' % (addr[0],addr[1],data))
				
				signature = ''
				key = ''

			elif ttype == 0:
				'''
					文件开始数据报处理
						（文件开头数据报没有文件内容）
						1、打开临时文件写指针
				'''
				if tpos == 1:
					tempk = tempfilepath
					if os.path.exists(tempk):
						tempk += str(random.randint(0,100000))
					wfp = open(tempk,'wb')
				'''
					文件结尾数据报处理：
						（文件结尾数据报没有文件内容）
						1、刷新缓冲区
						2、关闭指针
						3、文件重命名
				'''
				if tpos == 0:
					print fileName
					# 获得秘钥
					key = cu.rsaDe(COMSTR.THERE_PRIVATE, cipherkey)
					print len(databuffer)
					# 解密
					data = cu.FileDecrypt(key, databuffer, chunckSize)
					# 验证
					if not cu.VerifySignature(COMSTR.HERE_PUBLIC, data, signature):
						raise 'VerifySignature failed'
					else:
						print 'OK'
					wfp.write(data)
					wfp.flush()
					wfp.close()

					# 获取文件名，去除传输中的补足的'\x00'
					fileName = os.path.split(fileName.strip('\x00'))[-1]
					fileNameGroup = fileName.split('.')
					fileRName = fileNameGroup[0]
					fileEx = fileNameGroup[-1]

					# 文件重命名
					strname = tempDirectory+'\\'+fileRName+'.'+fileEx
					# 存在重复文件就替换
					if os.path.exists(strname):
						os.remove(strname)
					os.rename(tempk,strname)
					getInfo = addr[0] + '/' + str(addr[1])
					mess = '成功收到%s的文件 \"%s\" \n' %(getInfo,strname)
					self.writeConsole(mess)

					# 最后要置空
					signature = ''
					key = ''
					databuffer = ''

				'''
					处于传输中间的数据报处理：
						1、移动写文件的指针
						2、写入文件
				'''
				if tpos == 2:

					# 获得内容
					# 此段应该丢弃，可以保证每一段cipherdata中一定没有多余的'\x00'
					# cipherdata = cipherdata.rstrip('\x00')
					if (len(cipherdata) % 2048 != 0):
						print deviate
					# 加入缓冲区
					databuffer = insert(databuffer, cipherdata, deviate)

				# 返回确认报文
				self.udpSocket.sendto('1',addr)

	def stop(self):
		time.sleep(0.5)
		self.mutex.acquire()
		self.exit = True
		self.mutex.release()
		print self.exit

def insert(original, new, pos):
	return original[:pos] + new + original[pos:]

# 服务器处理主类
class UDPserver(threading.Thread):
	def __init__(self,port,console):
		threading.Thread.__init__(self)
		self.host = ''
		self.port = port
		self.Dsavepath = COMSTR.FILE_SAVE_PATH
		self.console = console

	def writeConsole(self,Message):
		self.console.insert(END,Message)

	def start(self):
		self._createUDPsocket()
		self.writeConsole('上线成功！当前端口 %d\n' %(self.port))
		self.run()

	def _createUDPsocket(self):
		self.udpSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		self.udpSocket.bind((self.host,self.port))

	def run(self):
		self.process = processThread(self.udpSocket,self.Dsavepath,self.console)
		self.process.setDaemon(True)
		self.process.start()

	def stop(self):
		self.process.stop()
		print self.process.isAlive()
#		self.udpSocket.close()
		print 'stop udpSocket'


class ClientUDP(threading.Thread):
	def __init__(self,host,port,mes,MessageBox):
		threading.Thread.__init__(self)
		self.clisock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
		self.host = host
		self.port = port
		self.address = (self.host,self.port)
		self.MessageBox = MessageBox
		self.mes = mes 
		self.TYPE_SWITCH = {
			'FILE': self.sendFile,
			'MESSAGE': self.sendMessage
		}
		self.datastruct = struct.Struct(COMSTR.PROTOCOL_DEFINE)

	def run(self):
		FILE_PREFIX = 'FILE'
		MESS_TYPE = self.mes.split(':')[0]
		send = self.TYPE_SWITCH[MESS_TYPE]
		send()


	def writeConsole(self,message):
		self.MessageBox.insert(END,message)

	def sendFile(self):
		filepath = self.mes[5:]
		print filepath
		rfp = open(filepath,'rb')

		# 发送头报文
		head = (0,1,filepath.encode(encoding = 'utf-8'),0,'','','')
		self.clisock.sendto(self.datastruct.pack(*head),self.address)
		self.clisock.recvfrom(1)

		# 机密的chunckSize，可以更改
		chunckSize = 2048 * 8
		# 一次性读入
		rdata = rfp.read()
		# 生成随机秘钥
		key = cu.RandomKey(64)
		# 加密
		data = cu.FileEncrypt(key, rdata, chunckSize)
		# 加密秘钥
		cipherkey = cu.rsaEn(COMSTR.THERE_PUBLIC, key)
		# 签名
		signature = cu.Signature(COMSTR.HERE_PRIVATE, rdata)

		# BUFFERSIZE 由报文格式决定，不能更改
		BUFFERSIZE = 2048
		length = len(data)
		point = 0
		while True:
			if (point >= length):
				break
			one = data[point : point + BUFFERSIZE]
			# 偏移量有待商榷
			value = (0, 2, filepath.encode(encoding = 'utf-8'), point, cipherkey, signature, one)
			packdata = self.datastruct.pack(*value)
			self.clisock.sendto(packdata,self.address)
			self.clisock.recvfrom(1)
			point += BUFFERSIZE

		end = (0, 0, filepath.encode(encoding = 'utf-8'), 0, cipherkey, signature ,'')
		self.clisock.sendto(self.datastruct.pack(*end),self.address)
		self.clisock.recvfrom(1)

		rfp.close()

		messStr1 =  '向%s/%d发送文件\"%s\"成功\n' %(self.host,self.port,filepath)
		print messStr1
		self.writeConsole(messStr1)

	def sendMessage(self):
		MESS_SIZE = 256
		# 生成随机秘钥
		key = cu.RandomKey(64)
		# 加密
		data = cu.FileEncrypt(key, self.mes, MESS_SIZE)
		# 加密秘钥
		cipherkey = cu.rsaEn(COMSTR.THERE_PUBLIC, key)
		# 签名
		signature = cu.Signature(COMSTR.HERE_PRIVATE, self.mes)
		# 发送
		value = (1, 0, '0', 0, cipherkey, signature, data)
		self.clisock.sendto(self.datastruct.pack(*value), self.address)
		self.clisock.recvfrom(1)
		

# 总界面
class SendWindows(object):
	def __init__(self):
		self.root = Tk()
		self.root.title('聊天框啦~~')
		self.root.geometry('450x230')
		self.root.resizable(height=False,width=False)
		self.app = Client(master = self.root)
		self.app.mainloop()

	def run(self):
		self.app.mainloop()

	def destroy(self):
		self.root.destroy()

if __name__ == '__main__':
	w = SendWindows()
	w.run()
