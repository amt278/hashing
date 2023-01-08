import hashlib 
import bcrypt

def hashing(pw):
	hash1 = hashlib.md5(pw.encode())
	print(f'your hash password: {hash1.hexdigest()}')
	print(hash1)
	return str(hash1.hexdigest())

def bhashing(pw):
	byte_pass = str.encode(pw)
	hashed = bcrypt.hashpw(byte_pass, bcrypt.gensalt())
	return hashed

def main():
	password = str(input('enter your password: '))
	'''hashed = hashing(password)
	with open('key.txt', 'r') as f:
		key = f.read()
		key.replace('\n', '')
		print(f'key: {key} type: {type(key)}\nhashed: {hashed} type: {hashed}')
		if key == hashed:
			print('matching')
		else:
			print('did not match')'''
	hashed = bhashing(password)
	'''with open('bkey.txt', 'wb') as f:
		f.write(hashed)'''
	with open('bkey.txt', 'rb') as f:
		key = f.read()
		if bcrypt.checkpw(password.encode(), key):
			print('matching')
		else:
			print('did not match')
	

if __name__ == '__main__':
	main()

