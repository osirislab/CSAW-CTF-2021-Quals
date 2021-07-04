import random


#Create randomized base stream (true_stream)
def base_stream():
	rand_stream = ''
	for _ in range(128):
		base = random.randint(0, 1)
		if base == 0:
			rand_stream += chr(120)
		else:
			rand_stream += chr(43)
	print(rand_stream)
	return rand_stream


#Checking challenger's stream of bases
def stream_check():
	errs = 0
	#Enter the number of bases you'd like to check
	print("How many bases would you like to check? ")
	str_len = int(input())
	#Enter the string of bases you want be checked, no quotes
	print("Please enter your " + str(str_len) + " bases: ")
	input_str = input()
	if len(input_str) == str_len:
		for i in range(0, str_len):
			if true_stream[i] != input_str[i]:
				errs += 1
	elif len(input_str) != str_len:
		print("You have not entered " + str(str_len) + " bases. Please try again.")
	print("Errors: " + str(errs))

	if (errs == 0) and (str_len == len(true_stream)):
		#give key
		with open('key.txt','r') as f:
			key = f.read()
		res = ''.join(format(ord(i), '08b') for i in key)
		print("The original string is : " + key)
		print("The string after binary conversion : " + res)
		#Check if arrows are correct
		def get_arrows():
			if basis == '+':
			    if bit == 1:
			        print('0.0 + 1.0i')
			    else: # bit == 0
			        print('1.0 + 0.0i')
			else: # basis == 'x'
			    if bit == 1:
			        print('-0.707 + 0.707i')
			    else: # bit == 0
			        print('0.707 + 0.707i')
	return errs


