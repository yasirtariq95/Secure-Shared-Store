import base64
import json
import math
import sqlite3
from os import getcwd
from os.path import basename
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
import os
import requests
# TODO: import additional modules as required

gt_username = 'ytariq3'   # TODO: Replace with your gt username within quotes
server_name = 'secure-shared-store'
databaseName = '/P4/Project4/server/application/serverClient.db'

''' <!!! DO NOT MODIFY THIS FUNCTION !!!>'''
def post_request(server_name, action, body, node_certificate, node_key):
	'''
		node_certificate is the name of the certificate file of the client node (present inside certs).
		node_key is the name of the private key of the client node (present inside certs).
		body parameter should in the json format.
	'''
	request_url= 'https://{}/{}'.format(server_name,action)
	request_headers = {
		'Content-Type': "application/json"
		}
	response = requests.post(
		url= request_url,
		data= json.dumps(body),
		headers = request_headers,
		cert = (node_certificate, node_key),
	)
	with open(gt_username, 'w') as f:
		f.write(response.content)
	return response

''' You can begin modification from here'''

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

def removeUser(username):
	with sqlite3.connect(databaseName) as con:
		cursorObj = con.cursor()

		cursorObj.execute(''' UPDATE user_client_sessions SET session_token= "0" WHERE username=? ''', [username])
                cursorObj.connection.commit()

def login(userName, privateKey):
	'''
		# TODO: Accept the
		 - user-id
		 - name of private key file(should be
		present in the userkeys folder) of the user.
		Generate the login statement as given in writeup and its signature.
		Send request to server with required parameters (action = 'login') using
		post_request function given.
		The request body should contain the user-id, statement and signed statement.
	'''

	statement = folderName() + 'as' + userName + 'logs into the server'

	pathForPrivateKey = getcwd() + '/userkeys/' + privateKey
	pathForNodeCert = getcwd() + "/certs/" + folderName() + ".crt"
	pathForNodekey = getcwd() + "/certs/" + folderName() + ".key"

	# link found from piazza
	# https://legrandin.github.io/pycryptodome/Doc/3.2/Crypto.Signature.pkcs1_15-module.html

	key = RSA.importKey(open(pathForPrivateKey).read())
	hashValue = SHA256.new(statement)
	signature = pkcs1_15.new(key).sign(hashValue)

	body = {"user-id": userName, "statement": statement, "signed-statement": base64.b64encode(signature)}
	response = post_request('secure-shared-store', 'login', body, pathForNodeCert, pathForNodekey)

	data = response.json()
	if data['status'] is not 200:
		return 'Login Denied!'

	if data['status'] == 200:
		session = str(data['session_token'])
		return session

def checkin(DID, securityFlag, userName):
	'''
		# TODO: Accept the
		 - DID
		 - security flag (1 for confidentiality  and 2 for integrity)
		Send the request to server with required parameters (action = 'checkin') using post_request().
		The request body should contain the required parameters to ensure the file is sent to the server.
	'''

	pathForNodeCert = getcwd() + "/certs/" + folderName() + ".crt"
	pathForNodekey = getcwd() + "/certs/" + folderName() + ".key"
	clientSession = folderName()

	pathForDoc = getcwd() + '/documents/checkin/' + DID
	fileName = basename(pathForDoc)
	openFile = open(pathForDoc, "r")
	readContents = openFile.read()
	openFile.close()

	body = {"client": clientSession, "user-id": userName, "DID": DID, "security_flag": securityFlag, "document": base64.b64encode(readContents)}
	response  = post_request(server_name, 'checkin', body, pathForNodeCert, pathForNodekey)

	data = response.json()
	status = str(data['status'])
	msg = str(data['message'])
	if status is not '200':
		return 'Job Status: ' + status + ' Server Message: ' + msg

	if data['status'] == '200':
		return 'Job Status: ' + status + ' Server Message: ' + msg

def checkout(DID, userName):
	'''
		# TODO: Accept the DID.
		Send request to server with required parameters (action = 'checkout') using post_request()
	'''
	pathForNodeCert = getcwd() + "/certs/" + folderName() + ".crt"
	pathForNodekey = getcwd() + "/certs/" + folderName() + ".key"
	pathForDoc = getcwd() + '/documents/checkout/' + DID
	clientSession = folderName()

	body = {"client": clientSession, "user-id": userName, "DID": DID}
	response = post_request(server_name, 'checkout', body, pathForNodeCert, pathForNodekey)
	data = response.json()
	status = str(data['status'])

	if status == '200':
		docFromServer = base64.b64decode(data['document'])
		openFile = open(pathForDoc, "w")
		openFile.write(docFromServer)
		openFile.close()

	msg = str(data['message'])
	if str(data['status']) != '200':
			return 'Job Status: ' + status + ' Server Message: ' + msg

	if str(data['status']) == '200':
			return 'Job Status: ' + status + ' Server Message: ' + msg


def grant(DID, TUID, R, T, userName):
	'''
		# TODO: Accept the
		 - DID
		 - target user to whom access should be granted (0 for all user)
		 - type of acess to be granted (1 - checkin, 2 - checkout, 3 - both checkin and checkout)
		 - time duration (in seconds) for which acess is granted
		Send request to server with required parameters (action = 'grant') using post_request()
	'''

	pathForNodeCert = getcwd() + "/certs/" + folderName() + ".crt"
	pathForNodekey = getcwd() + "/certs/" + folderName() + ".key"

	body = {"DID": DID, "TUID": TUID, "R": R, "T": T, "userId": userName}

	response = post_request(server_name, 'grant', body, pathForNodeCert, pathForNodekey)

	data = response.json()
	status = str(data['status'])
	msg = str(data['message'])
	if str(data['status']) != '200':
		return 'Job Status: ' + status + ' Server Message: ' + msg

	if str(data['status']) == '200':
		return 'Job Status: ' + status + ' Server Message: ' + msg

def delete(DID, userName):
	'''
		# TODO: Accept the DID to be deleted.
		Send request to server with required parameters (action = 'delete')
		using post_request().
	'''
	pathForNodeCert = getcwd() + "/certs/" + folderName() + ".crt"
	pathForNodekey = getcwd() + "/certs/" + folderName() + ".key"

	body = {"DID": DID, "userId": userName}
	response = post_request(server_name, 'delete', body, pathForNodeCert, pathForNodekey)

	data = response.json()
	status = str(data['status'])
	msg = str(data['message'])
	if status is not '200':
		return 'Job Status: ' + status + ' Server Message: ' + msg

	if data['status'] == '200':
		return 'Job Status: ' + status + ' Server Message: ' + msg

def logout(userName):
	'''
		# TODO: Ensure all the modified checked out documents are checked back in.
		Send request to server with required parameters (action = 'logout') using post_request()
		The request body should contain the user-id, session-token
	'''

	client = folderName()
	pathForNodeCert = getcwd() + "/certs/" + folderName() + ".crt"
	pathForNodekey = getcwd() + "/certs/" + folderName() + ".key"

	body = {"client": client}
	response = post_request(server_name, 'logout', body, pathForNodeCert, pathForNodekey)

	data = response.json()
        status = str(data['status'])
        msg = str(data['message'])
        listingFiles = data['allDoc']
        
        if len(listingFiles) == 0:
                print ('Job Status: 700 Server Message: Failed to log out')
                exit() #exit the program

	for files in listingFiles:
		pathForFile = os.getcwd() + '/documents/checkout/' + files
		openFile = open(pathForFile, 'r')
		readFile = openFile.read()
		openFile.close()

		body = {"client": client, "user-id": userName, "DID": files,
				"security_flag": "2", "document": base64.b64encode(readFile)}
		responseToCheckin = post_request(server_name, 'checkin', body, pathForNodeCert, pathForNodekey)
		addingDocument(files, userName)

	removeUser(userName)
        if str(data['status']) == '200':
                print ('Job Status: ' + status + ' Server Message: ' + msg)
                exit() #exit the program

def folderName():

	path = getcwd()
	parentFolder = basename(path)
	return parentFolder

def otherFunctions(token,userName):

	print "Please select the following option for further process"
	print "1. Checkin"
	print "2. Checkout"
	print "3. Grant"
	print "4. Delete"
	print "5. Logout"

	choose = raw_input("Your selection? ")

	if choose == "1":
		DID = raw_input("Enter document-id: ")
		securityFlag = raw_input("Which security do you want to set? ")
		print (checkin(DID, securityFlag, userName))

	if choose == "2":
		DID = raw_input("Enter document-id: ")
		print (checkout(DID, userName))
	if choose == "3":
		DID = raw_input('Enter document-id: ')
		TUID = raw_input('Which user you want to give access? ')
		R = raw_input('What access you want to grant? ')
		T = raw_input('For how long this access will remain: ')
		print (grant(DID, TUID, R, T, userName))
	if choose == "4":
		DID = raw_input('Enter document-id: ')
		print (delete(DID, userName))
	if choose == "5":
                logout(userName)

def main():

	print 'Authentication for: ', folderName()

	userName = raw_input("Please enter your user name: ")
	privateKey = raw_input("Please enter your private key: ")
        client = folderName()
        active = False

	token = login(userName, privateKey)

	if token == 'Login Denied!':
		print 'Either user-id or private-key is wrong'

	if token != 'Login Denied!':
		print 'Login Successful!'
                active = True
		otherFunctions(token,userName)

	while active:
                attempt = raw_input("Do you want to keep going? Enter Y to continue the program OR enter N to exit: ")
                if attempt != 'N':
                    otherFunctions(token,userName)
                else:
                    exit()

#
# 	'''
# 		# TODO: Authenticate the user by calling login.
# 		If the login is successful, provide the following options to the user
# 			1. Checkin
# 			2. Checkout
# 			3. Grant
# 			4. Delete
# 			5. Logout
# 		The options will be the indexes as shown above. For example, if user
# 		enters 1, it must invoke the Checkin function. Appropriate functions
# 		should be invoked depending on the user input. Users should be able to
# 		perform these actions in a loop until they logout. This mapping should
# 		be maintained in your implementation for the options.
# 	'''

if __name__ == '__main__':
	main()
