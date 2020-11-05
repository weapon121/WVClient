import re
import json
import base64
import requests
from socket  import *
from Crypto.Signature import pss
from Crypto.Hash import SHA1
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
import license_protocol_pb2


class PSSH:

	def __init__(self):

		self.path=None
		self.conten=None
		self.length=None
		self.data=None
		self.file_id=None
		self.kid=None

	def parse(self,object,type=1):

		if(type==1): # read file 
			self.path=object
			self.content=open(self.path,'r').read()
		else: # read data
			self.content=object

		try:
			offset=self.content.rfind('pssh')

			self.length= ord(self.content[offset-1])

			self.data =self.content[offset-4:offset+self.length-4]

			self.kid=self.content[offset-4+2+32:offset-4+32+2+16].encode('hex')

		except Exception as e:
			pass

class WidevineCDM:
	def __init__(self,url):
		self.private_key='308204a30201000282010100b5d1dc441883596c5d2722832d33cef4e4daa6e9959d6fbd83a9374527e533408448512e7d9509182ef750a7bd7bebbbf3d1d5653d38a41e68af7581d173b168e89b26494b06477b61f9f53a7755ade9cc293135178ffa8e0e6b9b0cafe2a150d6ef0cfd385952b0206fca5398a7dbf6faefd55f00029c15cdc420dece3c7844a72a3054f7d564f1a94f4e33d27ce8284c396e1b140e3568b009a3307ed36c62b3b395d7be57750e6f9155ccf72b3a668445fcae8d5de1e2c1c645b4c2b2a615c0c6a53bb866366b5e9b0b74c41b9fe49ba26bbb75b1cb89ca943c948d6212c07e259568dd4a2f7daf67357d209794c0ab5b4087a339e7fb6da56022ad61ef0902030100010282010018e3c326f1421dde373c51bdaa54f2ca547fd82496ce280b45f846b0295f776e280dac4b5476aff98708651aa9564af57e51a5c847a2b6d8d0d4e01da6da1319bce9ec4a5142694bab24681d1a53f8cc4e1dff75f8a54593e7c67441bedc23e028a42ddf8634b81c933c2a72da2d746fb1775e7ab44a272ad6f1b7dc38584fd03f0d122362bf18d00568bead150e35aa035156e4e3bda7bbe4cba7be3c3323487b9c43eb9a2f355949ceef58e874b47e4cd06564d7b62906207f893a70e3305421c6a77905f779a21f4820c72b44820fa21117b925fae391cef5aa896946ce9746d81f7abb23f885ddd6a0f7199ed33bf4f2a6e1d028b5d8266a56ee78525fa702818100d4cb413203d16ad1a3c5e0b2031ea0cf76e226e2110065feac40b77c15eeb2c0ce29f4a384571ed83da1714071528088965ecc2295d3c997c0a0e5c336132314d6d767e71691e1520393c7b62440df84fb5a5ac929269dab536c07bc05ce780112ed414cae484a56aa9539d6e822194b75c629e4ac622779b020d4923bde128702818100dabc9bc5f9cf0020d7c268ca1c517d249d7cfec42c1d3f8df41a83d00876b5ad48f96d9dea9f75ccc1259ae7b278c77a558589a026fe23a442be2c150b15eccd2d5e4de02eef1fadda668e0e17b21479d1414b9079d3cc80abb4623e137654e0bc2d1743879a2a9c5b9f8da7c5f36cbd77efdccc2ad5206e370fe28eda3e05ef028180383f1d9585d2d60461e0cd1ae09e38ed7dc41b7907fb6dfa5a37a5086497baa2221c8ef0a5eb8d58a539c640bd738c4c0e4b327435dc4c5e1369b431dc5a449c9e89438a9eb9a2b05607baf35733daa140fb4a220001980d90386ef6f125f92c777f45126ac2eafb6b8d94434d0aae5af6df91754367927da4e398acaaac7183028180393adddae7a86455337e7722625463d4bfabe3907a2650e9983393c74b5f9bdb31dba8f5875c9f5aaa32679c3592ea4634b812b1276298fab247c58adff2a5996d445e45c8a1e1fcffc693665686ce5aad08537802980acaa3a2378e1c537a93ae4871ecc63eece52a07cded569a8119f5967983a5b54b9deaa42a57cbfc2c5b028181009ceabe2ecf3709a1c85828e955f8960be47b9aa5beaa5d4e1ada1a6a3b40e00ce15f35fc1c85e9623ba93c1957950d4515f3de9ba8f06b551365ff02a486fca4f50b00df5946bc46f15f9bbe465655110f4d98fbc4f0b03da64734aa009a2dc36efed2e521180db057fcdc8f08b138b23fc08133db52c52d6a2c394efacfb051'.decode('hex')
		self.pub_key='30820122300d06092a864886f70d01010105000382010f003082010a0282010100b5d1dc441883596c5d2722832d33cef4e4daa6e9959d6fbd83a9374527e533408448512e7d9509182ef750a7bd7bebbbf3d1d5653d38a41e68af7581d173b168e89b26494b06477b61f9f53a7755ade9cc293135178ffa8e0e6b9b0cafe2a150d6ef0cfd385952b0206fca5398a7dbf6faefd55f00029c15cdc420dece3c7844a72a3054f7d564f1a94f4e33d27ce8284c396e1b140e3568b009a3307ed36c62b3b395d7be57750e6f9155ccf72b3a668445fcae8d5de1e2c1c645b4c2b2a615c0c6a53bb866366b5e9b0b74c41b9fe49ba26bbb75b1cb89ca943c948d6212c07e259568dd4a2f7daf67357d209794c0ab5b4087a339e7fb6da56022ad61ef090203010001'.decode('hex')
		self.license_proxy_address=('10.211.55.4',8888)
		self.license_request_data=None
		self.proxies={'http': 'http://127.0.0.1:1081', 'https': 'http://localhost:1081'}
		self.license_url=url #'https://widevine-proxy.appspot.com/proxy'
		self.header={"Cookie": ""}

	def generateRequestData(self,pssh_data): # 
		sock = socket(AF_INET,SOCK_STREAM)
		sock.connect(self.license_proxy_address)
		sock.send(pssh_data)
		recvData=sock.recv(10240)
		self.license_request_data=recvData

		#print 'License request data: \n',recvData.encode('hex')
		return recvData

	def getContentKey(self,lic_request_data):
		license=license_protocol_pb2.License()
		requestMessage=license_protocol_pb2.SignedMessage()
		responseMessage = license_protocol_pb2.SignedMessage()

		resp=requests.post(self.license_url,lic_request_data,headers=self.header,proxies=self.proxies)
		requestMessage.ParseFromString(lic_request_data)
		responseMessage.ParseFromString(resp.content)
		pubkey = RSA.importKey(self.pub_key)
		verifier = pss.new(pubkey)
		h = SHA1.new(requestMessage.msg)
		verifier.verify(h, requestMessage.signature)
		session_key=responseMessage.session_key
		license.ParseFromString(responseMessage.msg)
		rsakey = RSA.importKey(self.private_key)
		cipher = PKCS1_OAEP.new(rsakey)
		sessionKey=cipher.decrypt(session_key)
		context_enc='\x01'+'ENCRYPTION'+'\x00'+requestMessage.msg+'\x00'*3+chr(128)
		cobj = CMAC.new(sessionKey, ciphermod=AES)
		encryptKey=cobj.update(context_enc).digest()
		k= license.key[1]
		keyId = k.id.encode('hex')
		keyData = k.key[0:16]
		keyIv = k.iv[0:16]
		mode = AES.MODE_CBC
		cryptos = AES.new(encryptKey, mode, keyIv)
		dkey = cryptos.decrypt(keyData)
		print "		KID:",keyId,"KEY:",dkey.encode('hex')


class  Downloader(object):
	def __init__(self):
		self.url=None
		self.proxies = {'http': 'http://127.0.0.1:1081', 'https': 'http://localhost:1081'}
		self.header={'Cookie':  '','Range':'bytes=0-4096'}


	def download(self,url):
		resp=requests.get(url,headers=self.header,proxies=self.proxies)
		return  resp.content		


downloader=Downloader()
initData=downloader.download('https://bitmovin-a.akamaihd.net/content/art-of-motion_drm/video/1080_4800000/cenc_dash/init.mp4')

pssh=PSSH()
pssh.parse(initData,type=0) 

cdm=WidevineCDM('https://widevine-proxy.appspot.com/proxy')      #
data=cdm.generateRequestData(pssh.data)
cdm=cdm.getContentKey(data)
