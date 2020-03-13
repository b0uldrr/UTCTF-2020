## Challenge Title

* **Category:**  Crypto
* **Points:** 50

### Challenge
```
nc ecb.utctf.live 9003
```

### Solution
* **Author(s):** b0uldrr
* **Date:** 08/03/20 

We're given a remote sever (nc ecb.utctf.live 9003) which prompts for a string and then returns an encrypted version of your input. 

```
tmp@localhost:~/ctf/utctf/random_ecb$ nc ecb.utctf.live 9003
Input a string to encrypt (input 'q' to quit):
hello
Here is your encrypted string, have a nice day :)
97e38a5fa08a93b7dd96eee6369620e38a00c1eaaf5a5b23e34624cfeb65f57a65a790b028da1621f7b26bcfdad72f58
Input a string to encrypt (input 'q' to quit):
```

We're also provided with the server source code (server.py):

```
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits
from secret import flag

KEY = get_random_bytes(16)

def aes_ecb_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def encryption_oracle(plaintext):
    b = getrandbits(1)
    plaintext = pad((b'A' * b) + plaintext + flag, 16)
    return aes_ecb_encrypt(plaintext, KEY).hex()
    return 1

if __name__ == '__main__':
    while True:
        print("Input a string to encrypt (input 'q' to quit):")
        user_input = input()
        if user_input == 'q':
            break
        output = encryption_oracle(user_input.encode())
        print("Here is your encrypted string, have a nice day :)")
        print(output)
```

From reading through the source code, we can see that it does the following to encrypt our string:

1. Take our string input
1. Randomly determine whether to append a single 'A' to the front of our string or not (50% chance every time)
1. Append the flag string to the end of our input string
1. Pad the result so that the total length is a multiple of 16
1. Encrypt the output using AES ECB encryption and display the encrypted output to the screen

The weakness in this algorithm is that AES ECB is a block cipher that works by splitting our text into blocks of 16 bytes and then individually encrypting those blocks. Bytes 0-15 will produce the first 32 bits of the encrypted output. Bytes 16-31 will produce the second 32 bits of output, etc. Because the flag is appended to the end of our input string and because we can control the length of our input string, we can perform a "Chosen Plaintext" attack, where we fill up 15 of the first 16 bytes to be encrypted with our input string, leaving the last byte to be filled by the first character of the appended flag text. After the server responds with our encrypted text, we use a brute force algorithm to find out what that single flag character is by encrypting our known prefix plaintext with every printable character and comparing the encrypted output with that provided by the program. If the encryption output matches for those first blocks, then we have successfully determined the first flag character. Once we know the first character, we can repeat the attack by filling up 14 of the first 16 bytes with our own known string, which means the last 2 bytes will be the the first 2 characters of the flag. We can then repeat the brute force algorithm, this time using 14 bytes of our known input string plus the first known character of the flag, and then brute forcing the last byte, which will give use the 2nd flag character.

In the example below, the user inputs a choosen plaintext of 15 'a' characters. The encrypting algorithm appends the flag string on the end and then pads out the rest of the string to make it a multiple of 16 (represented by 'p' chars). It then breaks the entire string into blocks of 16 bytes and encrypts those blocks individually. The first block is our 15 'a' chars + the first char of the flag string:

```
Take the input string:
aaaaaaaaaaaaaaa

Append the flag:
aaaaaaaaaaaaaaaflag{abcdefgh}

Pad to a multiple of 16:
aaaaaaaaaaaaaaaflag{abcdefgh}ppp

Split into 16 byte blocks:

      block 1            block 2
+----------------+ +----------------+
|aaaaaaaaaaaaaaaf| |lag{abcdefgh}ppp|
+----------------+ +----------------+

Encrypt each block individually:

Block 1 output:
78fb5ec96e93a9012a568c5bc39a32a3

Block 2 output:
2e4830ec08a324715029ad0bc0938c7f

Append the outputs together and print it to screen:
78fb5ec96e93a9012a568c5bc39a32a32e4830ec08a324715029ad0bc0938c7f
```

With this output, we can now reconnect to the server and brute force our initial plaintext (15 x 'a') + all printable characters and then compare the output of block 1 to see if it matches. So we try "aaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaab", "aaaaaaaaaaaaaaac", etc. Eventually we will try "aaaaaaaaaaaaaaaf" and the output of block 1 will be the same as our initial input of just 15 'a' characters and we will know that the first character of the flag string is 'f'.

I wrote a python script to automate this process, and I expanded the attack to 32 bytes so that it would capture the full length of the flag string. The process was slightly complicated by the randomly appended 'A' character at the beginning of our input string because it meant that 50% of the time our input string was essentially unknown. To account for this, every time I tried a new input string I kept repeating it until I received 2 different encrypted outputs from the remote server. They were different because one of the inputs would have had the 'A' character appended to the front and the other had not. I then did the same for the brute force attack the followed, and both sets of responses had to match for the character to be accepted as a flag character.

```
#!/usr/bin/python3

from pwn import *
import string

flag = ""
conn = remote('ecb.utctf.live',9003)

# Take a string and send it to the remote sever and return the encrypted output
def sendString(string_to_send):
    conn.recvline()                 # "Input a string to encrypt (input 'q' to quit):"
    conn.sendline(string_to_send)
    conn.recvline()                 # "Here is your encrypted string, have a nice day :)"
    return conn.recvline()


# We're going to start with sending 31 'a' characters, which means the 32nd character will
# be filled with the first character of the flag. Once we know that, we'll send 30 characters and
# capture the first 2 flag characters. Keep repeating and reducing the number of characters
# we send until we have the entire flag.
for num_chars in range(31, -1, -1):

    got_both_responses = False
    response1 = ""
    response2 = ""

    # Send our known plaintext until we get 2 different encrypted responses from the remote
    # server, to accommodate for the randomly appended 'A' character prefix. We only care
    # about the first 2 blocks (bits 0-63) of the encrypted response, because that's what
    # we can control. We check to make sure we have 2 different reponses from the server to
    # accommodate for the randomly appended 'A' prefix. Once we have both of those responses
    # store them in variables response1 & response2.
    while(got_both_responses == False):

        plaintext = ('a' * num_chars)
        full_response = sendString(plaintext)
        response_first_2_blocks = full_response[0:64]

        if response1 == "":
            response1 = response_first_2_blocks

        elif response1 != response_first_2_blocks:
            response2 = response_first_2_blocks
            got_both = True

    # At this point we have our 2 different reponses from the server from our choosen plaintext.
    # Now we will brute force the sever with our choosen plaintext + all printable characters
    # and then check the returned encrypted output agaisnt our responses from above. If they
    # match, then we have succussfully determined the flag character. Again, we're going to
    # make sure that we get 2 different responses from the sever for each character so that we
    # account for the randomly appened 'A' prefix. Storing these responses in response_BF_1 and 2,
    # where BF stands for brute force.
    for char in string.printable:

        got_both_responses = False
        response_BF_1 = ""
        response_BF_2 = ""

        while(got_both_responses == False):
            plaintext = (('a' * num_chars) + flag) + char
            full_response = sendString(plaintext)
            response_first_2_blocks = full_response[0:64]

            # If our new encrypted response doens't match any of response1 or response2 captured
            # above, then don't bother checking the next one. We already know this character
            # is wrong. Not necessary to the algorithm, but it does save a lot of time.
            if(response_first_2_blocks != response1 and response_first_2_blocks != response1):
                break

            if response_BF_1 == "":
                response_BF_1 = response_first_2_blocks
            elif response_BF_1 != response_first_2_blocks:
                response_BF_2 = reponse_first_2_blocks
                got_both = True


        # Check the reponses from our initial choosen plaintext enquiry against those from our
        # brute force attack. If they match, then we have the next character of the flag.
        # Print the currentl known flag to to the screen.
        if((response1 == b1 or response1 == b2) and (response2 == b1 or response2 == b2)):
            flag += c
            print()
            print(flag)
            
            # We don't know how long the flag is.... so let's just quit if we find this char
            if c == "}":
                quit()

            break
```

**Flag** 
```
flag: utflag{3cb_w17h_r4nd0m_pr3f1x}
```
