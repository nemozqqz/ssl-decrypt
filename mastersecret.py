# cat test.enc | openssl rsautl -decrypt -inkey rsa.key | xxd
#gnutls-cli -p 443 www.baidu.com -d 9 --insecure --priority=NONE:+VERS-TLS1.0:+AES-128-CBC:+RSA:+SHA1:+COMP-NULL

from hashlib import md5,sha1,sha256
import hmac
from Crypto.Cipher import AES
import sys


"""
SSL 3.0 test data
prehex =  "0300c085be4f9984fd8106ba28fb3403532dc18f5bac4c1b0515dc0a5d429412ff2a99c2fec817c0ec0dfbdd7f86e5ee"
clienthex = "54abd288f8a2e5e505baa3bc6ad519054a41ebd4e317cd933501a6e3c818465c"
serverhex = "ad451896e4ba3d3eca39994936e30426c9d8f9baaf9a0baa68cfb38ed1dbdc98"
master secret should be "0e8b357249394872c4f7b3200db7af295e88693e821b92d805f3996e1c4fcb064529b72012c39f419dc5582d75d1526e"
"""

"""
TLS 1.0 test data (and TLS 1.1)
prehex = "030116ec7c6fdf1016b560721b6e7e7a4e52a52d7675ff26af2f6dd87c009af20316cfd4971b1a6e1b7fab7219b7c9f6"
clienthex = "54abd54f0f77c5cb576af7eb738446fc231419bab524cc5084bc6e93b9a8ac3d"
serverhex = "8b9f32964ac7029a59fa0022037c5804156f950c374800ae95e4be7c908fe318"
master secret should be "dda9ded11246652c17e590c6a0f5b5f01368d43bf62d3f7922be0c62ae1a87f480a26ca2491248568192af8cdea54dba"
"""

"""
TLS 1.2 test data
prehex = "0303961c8f739eaca758b4e2e32a55e5299ab5fe7df3728890022d94429bb18d7fbde59b81fa2e56b9fcb9c34e50255f"
clienthex = "54abe1db2e5cd5f48a5221da5385adb6b80428b3a4b0d85c780d35ae110736bf"
serverhex = "0432531820cdb2d8c47262bd5987530c601cd1b21d3e0b7595becbb947cc46e6"
mastersecret should be "7727a829c95f3e1875b8be2519b80aeca6674fa3b67e15620d7b08a26e7c8d9347e61a1c14f959895324b39ba70f5a25"
"""
"""
DTLS 1.0 
pre master key starts with "0100"
"""

versionList = ["TLS1.0","TLS1.1","TLS1.2","SSL3.0","DTLS1.0"]
masterSecretLabel = "master secret"
keyExpansionLabel = "key expansion"
macLen = 20
keyLen = 16
ivLen  = 16
def splitPreMasterSecret(premaster):
	length = len(premaster)
	return premaster[0:(length+1)/2],premaster[length/2:]

def pHash(result,secret,seed,hashfunc):
		a=hmac.new(secret,seed,hashfunc).digest()
		j=0
		while j<len(result):
				b = hmac.new(secret,a+seed,hashfunc).digest()
				todo = len(b)
				if j+todo > len(result):
						todo=len(result)-j
				result[j:j+todo] = b[0:todo]
				j+=todo
				a=hmac.new(secret,a,hashfunc).digest()

#TLS 1.0 and TLS 1.1 pseudo-random function
def prf10(result,secret,label,seed):
		labelandseed = label+seed
		s1,s2 = splitPreMasterSecret(secret)
		pHash(result,s1,labelandseed,md5)

		result2 = [0]*len(result)
		pHash(result2,s2,labelandseed,sha1)
		for i in range(len(result2)):
				s = ord(result[i]) ^ ord(result2[i])
				result[i] = chr(s)
	
#TLS 1.2 pseudo-random function
def prf12(result,secret,label,seed):
		labelandseed = label+seed
		pHash(result,secret,labelandseed,sha256)

#SSL 3.0 prf
def prf30(result,secret,label,seed):
	done=0
	i =0
	while done < len(result):
		pad = '' 
		for j in range(0,i+1):
			pad += chr(ord('A')+i)
		digest = sha1(pad[:i+1]+secret+seed).digest()

		t = md5(secret+digest).digest()
		todo = len(t)
		if len(result)-done < todo:
			todo = len(result)-done
		result[done:done+todo] = t[:todo]
		done += todo
		i+=1

def prfForVersion(version,result,secret,label,seed):
	if version ==  "SSL3.0":
			return prf30(result,secret,label,seed)
	elif version == "TLS1.0" or version == "TLS1.1" or version == "DTLS1.0":
			return prf10(result,secret,label,seed)
	elif version ==  "TLS1.2":
			return prf12(result,secret,label,seed)
	else:
		raise Exception("Unknow version type!")


def masterFromPreMasterSecret(version,preMasterSecret,clientRandom,serverRandom):
		seed = clientRandom+serverRandom
		mastersecret = [0]*48
		prfForVersion(version,mastersecret,preMasterSecret,masterSecretLabel,seed)
		mastersecret = ''.join(mastersecret)
		return mastersecret
	
def keysFromMasterSecret(version,masterSecret,clientRandom,serverRandom,macLen,keyLen,ivLen):
		seed = serverRandom + clientRandom
		n = 2*macLen + 2*keyLen + 2*ivLen
		keyBlock = [0]*n
		prfForVersion(version,keyBlock,masterSecret,keyExpansionLabel,seed)

		i=0
		clientMAC = keyBlock[i:i+macLen]
		clientMAC = ''.join(clientMAC)
		i+= macLen
		
		serverMAC = keyBlock[i:i+macLen]
		serverMAC = ''.join(serverMAC)
		i+=macLen

		clientKey = keyBlock[i:i+keyLen]
		clientKey = ''.join(clientKey)
		i+=keyLen

		serverKey = keyBlock[i:i+keyLen]
		serverKey = ''.join(serverKey)
		i+=keyLen

		clientIV = keyBlock[i:i+ivLen]
		clientIV = ''.join(clientIV)
		i+=ivLen

		serverIV = keyBlock[i:i+ivLen]
		serverIV = ''.join(serverIV)
		return clientMAC,serverMAC,clientKey,serverKey,clientIV,serverIV
				
def decrypt(key,iv,msg):
		cipher = AES.new(key,AES.MODE_CBC,iv)
		return cipher.decrypt(msg)

def test():
#	version = raw_input("version:")
#	if version not in versionList:
#		print "Unkown version"
#		print "Supported versions are",versionList
#		return
#	prehex    = raw_input("premaster hex:")
#	clienthex = raw_input("client hex:")
#	serverhex = raw_input("server hex:")
#	cmsg      = raw_input("client msg:")
#	smsg      = raw_input("server msg:")
	if len(sys.argv) < 2:
		print "Usage:",sys.argv[0],"input.txt"
		return
	fname = sys.argv[1]
	fd = open(fname,"r")
	version = fd.readline().strip()
	if version not in versionList:
		print "Unknown version!"
		print "Supported versions are",versionList
		return
	prehex = ''
	masterhex = ''
	secrethex = fd.readline().strip()
	secrets = secrethex.split()
	if secrets[0].lower().startswith("pre"):
		prehex = secrets[1]
	elif secrets[0].lower().startswith("master"):
		masterhex = secrets[1]
	else:
		print "Unknown",secrets[0]
		print "Please start with PRE or Master"
		return
	
	clienthex = fd.readline().strip()
	serverhex = fd.readline().strip()
	cmsg = fd.readline().strip()
	smsg = fd.readline().strip()
	fd.close()
	
	print "**key len now **",keyLen

	if prehex:
		pre_master_secret = prehex.decode('hex')
		assert len(pre_master_secret) == 48
	else:
		master_secret = masterhex.decode('hex')
		assert len(master_secret)==48

	
	client_random = clienthex.decode('hex')
	assert len(client_random) == 32
	
	server_random = serverhex.decode('hex')
	assert len(server_random)== 32

	if prehex:	
		master_secret =masterFromPreMasterSecret(version,pre_master_secret,client_random,server_random)
	print "pre master secret",prehex
	print "client random",clienthex
	print "server random",serverhex
	print "master secret",master_secret.encode('hex')

	cMac,sMac,cKey,sKey,cIV,sIV = keysFromMasterSecret(version,master_secret,client_random,server_random,macLen,keyLen,ivLen)
	print "cMAC",cMac.encode('hex')
	print "sMAC",sMac.encode('hex')
	print "cKey",cKey.encode('hex')
	print "sKey",sKey.encode('hex')
	print "cIV",cIV.encode('hex')
	print "sIV",sIV.encode('hex')

	print "-"*80
	print "client data start"
#	clientcipher = AES.new(cKey,AES.MODE_CBC,cIV)
#	cmsg = cmsg.decode('hex')
#	t=clientcipher.decrypt(cmsg)
	t= decrypt(cKey,cIV,cmsg.decode('hex'))
	print t
	print "client data end"

	print "-"*80
	print "server data start"
#	servercipher = AES.new(sKey,AES.MODE_CBC,sIV)
#	smsg = smsg.decode('hex')
	print decrypt(sKey,sIV,smsg.decode('hex'))
	print "server data end"
	print "-"*80
	
		

if __name__=='__main__':
	test()
	

