import base64
import binascii
import os
import shutil
import sqlite3
import thread
import threading
from threading import Timer
from os import path
from os.path import basename

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from flask import Flask, request, jsonify
from flask_restful import Resource, Api
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

# TODO: import additional modules as required

databaseName = "serverClient.db"


# def get_user_public_key(username):
# 	return os.getcwd() + "/userpublickeys/" + username + ".pub"


def connectingAndCreatingTables():
	with sqlite3.connect(databaseName) as con:
		cursorObj = con.cursor()

		# if table exist
		cursorObj.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='user_client_sessions' ''')

		# if not, then create
		if cursorObj.fetchone()[0] != 1:
			cursorObj.execute('CREATE TABLE user_client_sessions(session_token text, username text)')
			con.commit()

		# if table exist
		cursorObj.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='server_key' ''')

		# if not, then create
		if cursorObj.fetchone()[0] != 1:
			cursorObj.execute('CREATE TABLE server_key(key text, DID text)')
			con.commit()

		# if table exist
		cursorObj.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='user_access' ''')

		# if not, then create
		if cursorObj.fetchone()[0] != 1:
			cursorObj.execute('CREATE TABLE user_access(document text, user1Checkin text default 0, user1Checkout text default 0,'
							  ' user2Checkin text default 0, user2Checkout text default 0, user3Checkin text default 0, '
							  'user3Checkout text default 0)')
			con.commit()

                # if table exist
                cursorObj.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='user_check' ''')

                # if not, then create
                if cursorObj.fetchone()[0] != 1:
                        cursorObj.execute('CREATE TABLE user_check(client text, userName text)')
                        con.commit()

		# if table exist
		cursorObj.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='docMaster' ''')

		# if not, then create
		if cursorObj.fetchone()[0] != 1:
			cursorObj.execute('CREATE TABLE docMaster(document text, userName text)')
			con.commit()

def addingToDatabase(username, session_token):
	with sqlite3.connect(databaseName) as con:
		cursorObj = con.cursor()

		# check if session occurs
		cursorObj.execute(''' SELECT count(username) FROM user_client_sessions WHERE username=? ''', [username])

		if cursorObj.fetchone()[0] != 1:
			# no session active
			cursorObj.execute(''' INSERT INTO user_client_sessions(session_token, username) VALUES (?, ?) ''', [session_token, username])
		else:
			# session active
			cursorObj.execute(''' UPDATE user_client_sessions SET session_token=? WHERE username=? ''', [session_token, username])

		cursorObj.connection.commit()

def addingDocument(document, userName):
	with sqlite3.connect(databaseName) as con:
		cursorObj = con.cursor()

		userForCheckin = userName + 'Checkin'
		userForCheckout = userName + 'Checkout'
		# check if document exists
		cursorObj.execute(''' SELECT "{}" FROM user_access WHERE document=? '''.format(userForCheckin), [document])
		try:
			value = cursorObj.fetchone()[0]
		except:
			cursorObj.execute('''INSERT INTO user_access(document, "{}", "{}") VALUES (?, 1, 1) '''
							  .format(userForCheckin, userForCheckout), [document])
			value = 1
			cursorObj.execute('''INSERT INTO docMaster(document, userName) VALUES (?, ?) ''', [document, userName])

		cursorObj.connection.commit()
		return value

def gettingDocument(document, userName):
	with sqlite3.connect(databaseName) as con:
		cursorObj = con.cursor()
                userForCheckout = userName + 'Checkout'

		# check if document exists
		cursorObj.execute(''' SELECT "{}" FROM user_access WHERE document=? '''.format(userForCheckout), [document])
		try:
			value = cursorObj.fetchone()[0]
		except:
			value = 'Not Found!'

		cursorObj.connection.commit()
		return value

def savingKey(key, DID):
	with sqlite3.connect(databaseName) as con:
		cursorObj = con.cursor()

		cursorObj.execute(''' SELECT count(key) FROM server_key WHERE DID=? ''', [DID])

		if cursorObj.fetchone()[0] != 1:
			cursorObj.execute(''' INSERT INTO server_key(key, DID) VALUES (?, ?) ''', [key, DID])
		else:
			cursorObj.execute(''' UPDATE server_key SET key=? WHERE DID=? ''', [key, DID])

		cursorObj.connection.commit()

def getKey(DID):
	with sqlite3.connect(databaseName) as con:
		cursorObj = con.cursor()

		# check if document exists
		cursorObj.execute(''' SELECT key FROM server_key WHERE DID=? ''', [DID])
		try:
			value = cursorObj.fetchone()[0]
		except:
			value = 'Not Found!'

		cursorObj.connection.commit()
		return value

def getDocMaster(DID):
	with sqlite3.connect(databaseName) as con:
		cursorObj = con.cursor()

		# check if user exists
		cursorObj.execute('''SELECT userName FROM docMaster WHERE document=?''', [DID])
		try:
			value = cursorObj.fetchone()[0]
		except:
			value = 'No user'

		cursorObj.connection.commit()
		return value

def providePermission(DID, TUID, R):
	with sqlite3.connect(databaseName) as con:
		cursorObj = con.cursor()

		userForCheckin = TUID + 'Checkin'
		userForCheckout = TUID + 'Checkout'

		if TUID == '0':
			cursorObj.execute(''' UPDATE user_access SET user1Checkin = 1, user1Checkout = 1, user2Checkin = 1, user2Checkout = 
			1, user3Checkin = 1, user3Checkout = 1 WHERE document=? ''', [DID])
		elif R == '1':
			cursorObj.execute(''' UPDATE user_access SET "{}" = 1 WHERE document=? '''.format(userForCheckin), [DID])
		elif R == '2':
			cursorObj.execute(''' UPDATE user_access SET "{}" = 1 WHERE document=? '''.format(userForCheckout), [DID])
		elif R == '3':
			cursorObj.execute(''' UPDATE user_access SET "{}" = 1 WHERE document=? '''.format(userForCheckin), [DID])
			cursorObj.execute(''' UPDATE user_access SET "{}" = 1 WHERE document=? '''.format(userForCheckout), [DID])

		cursorObj.connection.commit()

def takingPermission(DID, TUID, R, master):
	with sqlite3.connect(databaseName) as con:
		cursorObj = con.cursor()

		masterUserCheckin = master + 'Checkin'
		masterUserCheckout = master + 'Checkout'
		userForCheckin = TUID + 'Checkin'
		userForCheckout = TUID + 'Checkout'

		if TUID == '0':
			cursorObj.execute(''' UPDATE user_access SET user1Checkin = 0, user1Checkout = 0, user2Checkin = 0, user2Checkout = 
			0, user3Checkin = 0, user3Checkout = 0 WHERE document=? ''', [DID])
			#owner gets the access only
			cursorObj.execute(''' UPDATE user_access SET "{}" = 1 WHERE document=? '''.format(masterUserCheckin), [DID])
			cursorObj.execute(''' UPDATE user_access SET "{}" = 1 WHERE document=? '''.format(masterUserCheckout), [DID])
		elif R == '1':
			cursorObj.execute(''' UPDATE user_access SET "{}" = 0 WHERE document=? '''.format(userForCheckin), [DID])
		elif R == '2':
			cursorObj.execute(''' UPDATE user_access SET "{}" = 0 WHERE document=? '''.format(userForCheckout), [DID])
		elif R == '3':
			cursorObj.execute(''' UPDATE user_access SET "{}" = 0 WHERE document=? '''.format(userForCheckin), [DID])
			cursorObj.execute(''' UPDATE user_access SET "{}" = 0 WHERE document=? '''.format(userForCheckout), [DID])

		cursorObj.connection.commit()

def deletingDoc(DID):
	with sqlite3.connect(databaseName) as con:
		cursorObj = con.cursor()

		cursorObj.execute('''DELETE FROM user_access WHERE document = ?''', [DID])
		cursorObj.execute('''DELETE FROM docMaster WHERE document = ?''', [DID])
		cursorObj.execute('''DELETE FROM server_key WHERE DID=?''', [DID])

		cursorObj.connection.commit()

connectingAndCreatingTables()
secure_shared_service = Flask(__name__)
api = Api(secure_shared_service)

class welcome(Resource):
	def get(self):
		return "Welcome to the secure shared server!"

class login(Resource):
	def post(self):
		data = request.get_json()

		# client signature
		signatureFromServer = binascii.a2b_base64(data['signed-statement'])
 		username = str(data['user-id'])
 		statement = str(data['statement'])

 		pathForPublicKey = os.getcwd() + '/userpublickeys/' + username + '.pub'

		keyForServer = RSA.importKey(open(pathForPublicKey).read())
 		hashForServer = SHA256.new(statement)

 		matches = False

 		# do the two signatures matches?
 		try:
			pkcs1_15.new(keyForServer).verify(hashForServer, signatureFromServer)
 			matches = True
 		except (ValueError, TypeError):
 			matches = False
 		# TODO: Implement login functionality
 		'''
# 		# TODO: Verify the signed statement.
# 			Response format for success and failure are given below. The same
# 			keys ('status', 'message', 'session_token') should be used.
# 		'''
 		if matches:
 			session_token = base64.b64encode(os.urandom(16)) # TODO: Generate session token
 			# Similar response format given below can be used for all the other functions
			response = {
				'status': 200,
				'message': 'Login Successful',
				'session_token': session_token,
			}
			addingToDatabase(username, session_token)
		else:
			response = {
				'status': 700,
				'message': 'Login Failed'
			}
		return jsonify(response)
# https://nitratine.net/blog/post/python-encryption-and-decryption-with-pycryptodome/
# used above link for AES encryption
class checkin(Resource):
 	def post(self):
		data = request.get_json()
# # 		# TODO: Implement checkin functionality
# #         '''
# # 		Expected response status codes:
# # 		1) 200 - Document Successfully checked in
# # 		2) 702 - Access denied to check in
# # 		3) 700 - Other failures
# # 	'''
		valueForFlag = str(data['security_flag'])
		docFromClient = base64.b64decode(data['document'])
		DIDFromClient = str(data['DID'])
		pathForDoc = os.getcwd() + '/documents/' + DIDFromClient + '.enc'
		signedDoc = os.getcwd() + '/documents/' + DIDFromClient + '.signed'
		currentDir = os.getcwd()
		serverPubKeyPath = os.path.abspath(os.path.join(currentDir, os.pardir)) + '/certs/secure-shared-store.pub'
		username = str(data['user-id'])
		clientSession = str(data['client'])
		initialDoc = os.path.abspath(os.path.join(__file__, "../../../")) + '/' + clientSession + '/documents/checkin/' + '/' + DIDFromClient
		match = basename(initialDoc)
		accessPermission = addingDocument(DIDFromClient, username)

		if DIDFromClient != match:
			response = {
				'status': 700,
				'message': 'Document not found!'
			}

		elif accessPermission == '0':
			response = {
				'status': 702,
				'message': 'You dont have access to checkin'
			}

		elif valueForFlag == '1':
			keyForServer = get_random_bytes(32)
			createCipher = AES.new(keyForServer, AES.MODE_CBC)
			cipherText = createCipher.encrypt(pad(docFromClient, AES.block_size))

			writeFile = open(pathForDoc, "wb")
			writeFile.write(createCipher.iv)
			writeFile.write(cipherText)
			writeFile.close()

			serverPubKey = RSA.importKey(open(serverPubKeyPath).read())
			cipherForPubKey = PKCS1_OAEP.new(serverPubKey)
			cipherTextForPubKey = base64.b64encode(cipherForPubKey.encrypt(keyForServer))
			savingKey(cipherTextForPubKey, DIDFromClient)

			response = {
					'status': 200,
					'message': 'Document successfully checked-in with confidentiality'
				}

		elif valueForFlag == '2':
			userPriKey = os.path.abspath(os.path.join(__file__, "../../../")) + '/' + clientSession + '/userkeys/' + username + '.key'
			serverDocLoc = os.getcwd() + '/documents/' + DIDFromClient
			key = RSA.importKey(open(userPriKey).read())
			hashValue = SHA256.new(docFromClient)
			signature = pkcs1_15.new(key).sign(hashValue)
			docSigned = open(signedDoc, "wb")
			docSigned.write(base64.b64encode(signature))
			docSigned.close()
			docLocation = open(serverDocLoc, "w")
			docLocation.write(docFromClient)
			docLocation.close()

			response = {
				'status': 200,
				'message': 'Document successfully checked-in with integrity'
			}

		return jsonify(response)

class checkout(Resource):
 	def post(self):
 		data = request.get_json()
		DIDFromClient = str(data['DID'])
		username = str(data['user-id'])
		flag = False
		clientSession = str(data['client'])
                docMaster = getDocMaster(DIDFromClient)
		accessPermission = gettingDocument(DIDFromClient, username)
# # 		# TODO: Implement checkout functionality
# #         '''
# # 		Expected response status codes
# # 		1) 200 - Document Successfully checked out
# # 		2) 702 - Access denied to check out
# # 		3) 703 - Check out failed due to broken integrity
# # 		4) 704 - Check out failed since file not found on the server
# # 		5) 700 - Other failures
# #         '''
		# For Confidentiality
		docOnServer = os.getcwd() + '/documents/' + DIDFromClient
		desDoc = os.path.abspath(os.path.join(__file__, "../../../")) + '/' + clientSession + '/documents/checkout/' + '/' + DIDFromClient
		signDocOnServer = os.getcwd() + '/documents/' + DIDFromClient + '.signed'
		serverPrivateKeyPath = os.path.abspath(os.path.join(os.getcwd(), os.pardir)) + '/certs/secure-shared-store.key'
		confKey = getKey(DIDFromClient)
		match = basename(docOnServer)
		print "match: " + match

		if DIDFromClient != match:
			response = {
				'status': 704,
				'message': 'Check out failed since file not found on the server!'
			}

		elif accessPermission == '0' or accessPermission == 'Not Found!':
			response = {
				'status': 702,
				'message': 'Access denied to check out'
			}

		elif confKey != 'Not Found!':

			pathForDoc = os.getcwd() + '/documents/' + DIDFromClient + '.enc'
			serverKey = RSA.importKey(open(serverPrivateKeyPath).read())
			createCipher = PKCS1_OAEP.new(serverKey)
			decServerKey = createCipher.decrypt(base64.b64decode(confKey))

			readFile = open(pathForDoc, "rb")
			valueForIV = readFile.read(16)
			readContents = readFile.read()
			readFile.close()

			decryptCipher = AES.new(decServerKey, AES.MODE_CBC, iv=valueForIV)
			originalDoc = unpad(decryptCipher.decrypt(readContents), AES.block_size)
			response = {
				'status': 200,
				'message': 'Document successfully checked out',
				'document': base64.b64encode(originalDoc)
			}

		elif accessPermission !=0 or accessPermission != 'Not Found!':
			signed = open(signDocOnServer).read()
			signatureForServer = binascii.a2b_base64(signed)
			pathForPublicKey = os.getcwd() + '/userpublickeys/' + docMaster + '.pub'
			keyFromServer = RSA.importKey(open(pathForPublicKey).read())
			fileName = open(docOnServer, "r")
			readContents = fileName.read()
			fileName.close()
			hashFromServer = SHA256.new(readContents)

			try:
				pkcs1_15.new(keyFromServer).verify(hashFromServer, signatureForServer)
				flag = True
			except (ValueError, TypeError):
				flag = False

			if flag:
				response = {
					'status': 200,
					'message': 'Document successfully checked out',
					'document': base64.b64encode(readContents)
				}

			else:
				response = {
					'status': 703,
					'message': 'Check out failed due to broken integrity'
				}

		else:
			response = {
				'status': 700,
				'message': 'Other Failures'
			}
		return jsonify(response)
# #
class grant(Resource):
 	def post(self):
 		data = request.get_json()
		DIDFromClient = str(data['DID'])
		username = str(data['userId'])
		rightAccess = str(data['R'])
		time = int(data['T'])
		target = str(data['TUID'])
		findMaster = getDocMaster(DIDFromClient)
# # 		# TODO: Implement grant functionality
# # 	'''
# # 		Expected response status codes:
# # 		1) 200 - Successfully granted access
# # 		2) 702 - Access denied to grant access
# # 		3) 700 - Other failures
# # 	'''
		if findMaster != username:
			response = {
				'status': 702,
				'message': 'Access denied to grant access'
			}

		elif findMaster == username:
			if rightAccess == "1":
				providePermission(DIDFromClient, target, rightAccess)
				accessTime = threading.Timer(time, takingPermission, [DIDFromClient, target, rightAccess, findMaster]).start()
				response = {
					'status': 200,
					'message': 'Successfully granted access'
				}
			if rightAccess == "2":
				providePermission(DIDFromClient, target, rightAccess)
				accessTime = threading.Timer(time, takingPermission, [DIDFromClient, target, rightAccess, findMaster]).start()
				response = {
					'status': 200,
					'message': 'Successfully granted access'
				}
			if rightAccess == "3":
				providePermission(DIDFromClient, target, rightAccess)
				accessTime = threading.Timer(time, takingPermission, [DIDFromClient, target, rightAccess, findMaster]).start()
				response = {
					'status': 200,
					'message': 'Successfully granted access'
				}

		else:
			response = {
				'status': 700,
				'message': 'Other failures'
			}
		return jsonify(response)
# #
class delete(Resource):
 	def post(self):
 		data = request.get_json()
		DIDFromClient = str(data['DID'])
		username = str(data['userId'])
		findMaster = getDocMaster(DIDFromClient)
		pathForDoc = os.getcwd() + '/documents/' + DIDFromClient
		confDoc = os.getcwd() + '/documents/' + DIDFromClient + '.enc'
		signDoc = os.getcwd() + '/documents/' + DIDFromClient + '.signed'
# # 		# TODO: Implement delete functionality
# # 	'''
# # 		Expected response status codes:
# # 		1) 200 - Successfully deleted the file
# # 		2) 702 - Access denied to delete file
# # 		3) 704 - Delete failed since file not found on the server
# # 		4) 700 - Other failures
# # 	'''
		if findMaster == 'No user':
			response = {
				'status': 704,
				'message': 'Delete failed since file not found on the server'
			}

		elif findMaster != username:
			response = {
				'status': 702,
				'message': 'Access denied to delete file'
			}

		elif findMaster == username:
			try:
				os.remove(pathForDoc)
			except:
				''
			try:
				os.remove(confDoc)
			except:
				''
			try:
				os.remove(signDoc)
			except:
				''
			deletingDoc(DIDFromClient)
			response = {
				'status': 200,
				'message': 'Successfully deleted the file'
			}

		else:
			response = {
				'status': 700,
				'message': 'Other failures'
			}
		return jsonify(response)
# #
class logout(Resource):
 	def post(self):
 		data = request.get_json()
		clientSession = str(data['client'])

                checkoutDocs = os.path.abspath(os.path.join(__file__, "../../../")) + "/" + clientSession + "/documents/checkout" 
		listAllFiles = os.listdir(checkoutDocs)
                response = {
			'status': 200,
    			'message': 'Successfully logged out',				
                        'allDoc': listAllFiles
		}
# # 		# TODO: Implement logout functionality
# # 	'''
# # 		Expected response status codes:
# # 		1) 200 - Successfully logged out
# # 		2) 700 - Failed to log out
# # 	'''
		return jsonify(response)
#
api.add_resource(welcome, '/')
api.add_resource(login, '/login')
api.add_resource(checkin, '/checkin')
api.add_resource(checkout, '/checkout')
api.add_resource(grant, '/grant')
api.add_resource(delete, '/delete')
api.add_resource(logout, '/logout')

def main():
	secure_shared_service.run(debug=True)

if __name__ == '__main__':
	main()
