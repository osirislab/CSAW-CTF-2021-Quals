import codecs, base64
from Crypto.Util.number import long_to_bytes

MORSE_CODE_DICT = { 'A':'.-', 'B':'-...',
                    'C':'-.-.', 'D':'-..', 'E':'.',
                    'F':'..-.', 'G':'--.', 'H':'....',
                    'I':'..', 'J':'.---', 'K':'-.-',
                    'L':'.-..', 'M':'--', 'N':'-.',
                    'O':'---', 'P':'.--.', 'Q':'--.-',
                    'R':'.-.', 'S':'...', 'T':'-',
                    'U':'..-', 'V':'...-', 'W':'.--',
                    'X':'-..-', 'Y':'-.--', 'Z':'--..',
                    '1':'.----', '2':'..---', '3':'...--',
                    '4':'....-', '5':'.....', '6':'-....',
                    '7':'--...', '8':'---..', '9':'----.',
                    '0':'-----', ', ':'--..--', '.':'.-.-.-',
                    '?':'..--..', '/':'-..-.', '-':'-....-',
                    '(':'-.--.', ')':'-.--.-'}

def decrypt(enc):
	enc += ' '
	dec = ''
	citext = ''
	for letter in enc:
		if (letter != ' ') and (letter != '/'):
			citext += letter
		else:
			if letter == ' ':
				dec += list(MORSE_CODE_DICT.keys())[list(MORSE_CODE_DICT.values()).index(citext)]
				citext = ''
			if letter == '/':
				dec += ' '
	b64_string = ''.join([chr(int(d)) for d in dec.split()])
	base64_bytes = b64_string.encode("ascii")
	rsa_bytes = base64.b64decode(base64_bytes)
	rsa = rsa_bytes.decode("ascii")
	c = int(rsa.split()[-1])
	rot = long_to_bytes(int(c ** (1/3)))
	return codecs.decode(rot.decode("utf-8"),'rot_13')

enc = "---.. ....- /.---- ----- ..... /-.... ..... /..... --... /--... ...-- /-.... ---.. /---.. ..... /.---- ..--- ..--- /--... ---.. /-.... ---.. /-.... ----. /..... .---- /--... ----. /---.. ....- /---.. ----. /.---- .---- ----. /--... --... /.---- ..--- ..--- /-.... ..... /..... ..--- /--... --... /---.. ....- /-.... ----. /.---- .---- ----. /--... --... /-.... ---.. /----. ----. /....- ----. /--... ----. /---.. ....- /----. ----. /..... .---- /--... --... /---.. ....- /---.. ..... /..... .---- /--... ---.. /.---- ----- -.... /---.. .---- /..... ..--- /--... --... /---.. ....- /-.... ..... /....- ----. /--... --... /.---- ..--- ..--- /---.. ----. /.---- ..--- ----- /--... ---.. /.---- ----- -.... /----. ----. /....- ----. /--... --... /.---- ----- -.... /----. ----. /..... .---- /--... ---.. /---.. ....- /-.... ----. /.---- .---- ----. /--... ---.. /.---- ----- -.... /--... ...-- /.---- ..--- ..--- /--... --... /-.... ---.. /.---- ----- --... /....- ----. /--... --... /---.. ....- /---.. .---- /.---- ..--- ----- /--... --... /.---- ----- -.... /--... ...-- /....- ---.. /--... --... /.---- ----- -.... /.---- ----- --... /.---- ..--- ..--- /--... --... /.---- ..--- ..--- /---.. ----. /....- ---.. /--... --... /-.... ---.. /--... --... /.---- ..--- .---- /--... --... /.---- ..--- ..--- /--... --... /..... ...-- /--... ---.. /.---- ..--- ..--- /.---- ----- ...-- /.---- ..--- .---- /--... ----. /-.... ---.. /--... --... /.---- ..--- ..--- /--... ---.. /.---- ..--- ..--- /-.... ----. /.---- ..--- .---- /--... ---.. /.---- ..--- ..--- /----. ----. /.---- ..--- ..--- /--... --... /.---- ..--- ..--- /-.... ----. /.---- ..--- ..--- /--... --... /.---- ----- -.... /---.. ..... /.---- ..--- ..--- /--... --... /---.. ....- /---.. ..... /.---- ..--- ----- /--... ---.. /-.... ---.. /---.. .---- /.---- ..--- ----- /--... ---.. /-.... ---.. /----. ----. /..... .---- /--... ---.. /.---- ..--- ..--- /-.... ..... /.---- .---- ----. /--... --... /-.... ---.. /---.. ----. /..... ----- /--... ---.. /.---- ..--- ..--- /--... --... /....- ---.. /--... --... /-.... ---.. /----. ----. /....- ---.. /--... ---.. /.---- ..--- ..--- /---.. ..... /.---- ..--- ----- /--... ----. /---.. ....- /---.. ----. /.---- ..--- ----- /--... --... /.---- ..--- ..--- /--... ...-- /.---- ..--- .---- /--... ---.. /---.. ....- /--... ...-- /.---- ..--- ..--- /--... --... /.---- ----- -.... /-.... ----. /.---- .---- ----. /--... ---.. /-.... ---.. /---.. ----. /.---- ..--- ----- /--... ---.. /.---- ----- -.... /.---- ----- ...-- /..... ----- /--... ----. /---.. ....- /-.... ----. /..... .---- /--... --... /.---- ..--- ..--- /--... ...-- /.---- .---- ----. /--... ---.. /-.... ---.. /---.. ..... /..... ...-- /--... --... /---.. ....- /---.. ----. /..... ...-- /--... --... /-.... ---.. /---.. .---- /..... ----- /--... ----. /-.... ---.. /----. ----. /.---- ..--- .---- /--... ---.. /.---- ..--- ..--- /--... --... /..... .---- /--... ---.. /---.. ....- /---.. ..... /.---- ..--- .---- /--... --... /.---- ..--- ..--- /---.. ..... /.---- ..--- .---- /--... --... /.---- ----- -.... /---.. .---- /..... ...-- /--... --... /.---- ..--- ..--- /---.. .---- /....- ---.. /--... ---.. /.---- ..--- ..--- /-.... ----. /.---- ..--- ----- /--... ---.. /-.... ---.. /-.... ----. /.---- ..--- ..--- /--... --... /.---- ----- -.... /-.... ..... /..... ----- /--... ----. /---.. ....- /---.. ----. /....- ----. /--... --... /.---- ..--- ..--- /-.... ..... /..... ...-- /--... --... /-.... ---.. /---.. .---- /..... ..--- /--... ---.. /-.... ---.. /-.... ----. /.---- ..--- ----- /--... ---.. /.---- ----- -.... /-.... ----. /.---- ..--- ----- /--... --... /-.... ---.. /-.... ----. /.---- ..--- .---- /--... --... /.---- ..--- ..--- /--... --... /....- ----. /--... ---.. /---.. ....- /---.. .---- /....- ---.. /--... --... /.---- ..--- ..--- /.---- ----- ...-- /.---- ..--- .---- /--... --... /.---- ----- -.... /----. ----. /....- ----. /--... ---.. /-.... ---.. /--... --... /..... ----- /--... ---.. /.---- ----- -.... /---.. ..... /....- ---.. /--... --... /.---- ..--- ..--- /---.. ..... /.---- .---- ----. /--... ---.. /.---- ----- -.... /---.. ----. /....- ----. /--... ----. /-.... ---.. /--... ...-- /..... ..--- /--... ----. /---.. ....- /-.... ..... /.---- .---- ----. /--... ---.. /.---- ----- -.... /.---- ----- --... /.---- ..--- ----- /--... --... /.---- ..--- ..--- /--... --... /..... ----- /--... --... /.---- ----- -.... /-.... ..... /..... ----- /--... --... /---.. ....- /---.. ..... /.---- ..--- .---- /--... ---.. /.---- ..--- ..--- /.---- ----- ...-- /.---- .---- ----. /--... ---.. /.---- ----- -.... /.---- ----- ...-- /.---- ..--- ..--- /--... ---.. /.---- ..--- ..--- /---.. ..... /..... ..--- /--... --... /.---- ..--- ..--- /.---- ----- ...-- /..... ..--- /--... --... /.---- ----- -.... /.---- ----- ...-- /.---- .---- ----. /--... --... /---.. ....- /-.... ..... /..... ..--- /--... ---.. /-.... ---.. /---.. ----. /....- ---.. /--... --... /---.. ....- /-.... ----. /..... ----- /--... ---.. /---.. ....- /.---- ----- --... /.---- ..--- ..--- /--... ---.. /.---- ..--- ..--- /-.... ----. /.---- ..--- .---- /--... --... /-.... ---.. /-.... ..... /..... .---- /--... --... /.---- ..--- ..--- /--... --... /.---- ..--- .---- /--... --... /.---- ..--- ..--- /--... --... /..... ----- /--... ---.. /-.... ---.. /---.. .---- /..... ----- /--... ---.. /.---- ..--- ..--- /-.... ----. /.---- ..--- ----- /--... ---.. /.---- ----- -.... /----. ----. /.---- ..--- .---- /--... ---.. /.---- ..--- ..--- /--... ...-- /.---- ..--- .---- /--... ---.. /-.... ---.. /.---- ----- ...-- /..... .---- /--... ----. /-.... ---.. /---.. .---- /....- ----. /--... --... /.---- ..--- ..--- /---.. ..... /....- ----. /--... ---.. /---.. ....- /---.. ----. /..... ..--- /--... ---.. /.---- ----- -.... /-.... ----. /.---- ..--- ----- /--... ---.. /-.... ---.. /-.... ----. /..... .---- /--... --... /-.... ---.. /----. ----. /.---- ..--- .---- /--... ---.. /---.. ....- /---.. ----. /.---- ..--- ----- /--... ---.. /.---- ----- -.... /---.. ..... /.---- .---- ----. /--... ----. /-.... ---.. /---.. .---- /..... .---- /-.... --... /.---- ----- ----. /---.. ..... /.---- ----- ...-- /---.. ----- /---.. ...-- /-.... ..... /.---- ..--- ..--- /-.... --... /.---- ----- ----. /--... --... /.---- ----- ...-- /---.. ----- /---.. ...-- /-.... ..... /.---- ..--- ----- /--... --... /---.. ....- /-.... ----. /..... .---- /--... ---.. /.---- ----- -.... /--... ...-- /.---- ..--- .---- /--... --... /.---- ..--- ..--- /----. ----. /.---- ..--- ..--- /--... --... /-.... ---.. /-.... ..... /....- ----. /--... --... /.---- ..--- ..--- /----. ----. /....- ----. /--... ---.. /-.... ---.. /---.. ----. /..... ..--- /--... --... /.---- ..--- ..--- /---.. .---- /.---- ..--- .---- /--... --... /-.... ---.. /----. ----. /..... ----- /--... --... /.---- ..--- ..--- /--... --... /..... ...-- /--... ----. /---.. ....- /--... --... /..... ----- /--... ---.. /.---- ..--- ..--- /---.. ----. /.---- ..--- ..--- /--... --... /.---- ..--- ..--- /.---- ----- --... /.---- ..--- ..--- /--... --... /.---- ----- -.... /---.. ----. /....- ---.. /--... ----. /---.. ....- /-.... ..... /..... ----- /--... ----. /---.. ....- /-.... ..... /..... ..--- /--... --... /.---- ..--- ..--- /--... --... /..... .---- /--... --... /---.. .---- /-.... .---- /-.... .----"
print("The answer is",decrypt(enc))