# OvertheWire Bandit Wargame Walkthrough
Walkthrough of the bandit wargame at overthewire.org

Link to wargame: http://overthewire.org/wargames/bandit/

### Level 0
<pre>
ssh -p 2220 bandit0@bandit.labs.overthewire.org
	bandit0
cat readme #dispays the contents of the readme file in the home directory

</pre>
### Level 1
<pre>
ssh -p 2220 bandit0@bandit.labs.overthewire.org
	boJ9jbbUNNfktd78OOpsqOltutMc3MY1
cat ./-

Here the password is in the "-" file. However this is a special character in bash, thus "./" has to be appended to signal that a file path is being provided.

</pre>
### Level 2
<pre>
ssh -p 2220 bandit2@bandit.labs.overthewire.org
	CV1DtqXWVFXTvM2F0k09SHz0YwRINYA9
cat spaces\ in\ this\ filename


The file containing the password has spaces, thus "\" is used to escape the special <space> characters. This is automatically done if one presses tab after typing in the first few characters of the file name.

</pre>
### Level 3
<pre>
ssh -p 2220 bandit3@bandit.labs.overthewire.org
	UmHadQclWmgdLOKQ3YNgjWxGoRMb5luK

find -name "*" #find allows one to search for a file by name in the cwd and all subdirectories
cat ./inhere/.hidden

ALT

cd inhere
ls -a # -a flag shows all files as well
cat .hidden

</pre>
### Level 4
<pre>
ssh -p 2220 bandit4@bandit.labs.overthewire.org
	pIwrPrtPN36QITSp3EQaw936yaFoFgAB

cd inhere
ls
file ./*    #Observe here how ./ is appended to * to list all files as the file names begin with -

''' #Output
./-file00: data
./-file01: data
./-file02: data
./-file03: data
./-file04: data
./-file05: data
./-file06: data
./-file07: ASCII text
./-file08: data
./-file09: data
'''

#Here we can see that only ./-file7 is human readable, thus we open that file
cat ./-file07

</pre>
### Level 5
<pre>
ssh -p 2220 bandit5@bandit.labs.overthewire.org
	koReBOKuIDDepwhWk7jZC0RTdopnAYKh]

cd inhere
find . -type f -size 1033c #Here we use find to search for a file of size 1033 bytes (https://www.ostechnix.com/find-files-bigger-smaller-x-size-linux/)
cat ./maybehere07/.file2


</pre>
### Level 6
<pre>
ssh -p 2220 bandit6@bandit.labs.overthewire.org
	DXjZPULLxYr17uwoI01bNLQbtFemEgo7

find . -type f -size 33c -user bandit7 -group bandit6

#Here we just append more conditions (group and user) to the find command.

cat ./var/lib/dpkg/info/bandit7.password

</pre>
### Level 7
<pre>
ssh -p 2220 bandit7@bandit.labs.overthewire.org
	HKBPTKQnIay4Fw76bEy8PVxKEDQRKTzs

grep "millionth" data.txt
# grep is used to search for strings within text files and display the line containing the matched string {https://www.linode.com/docs/tools-reference/tools/how-to-grep-for-text-in-files/}

</pre>
### Level 8
<pre>
ssh -p 2220 bandit8@bandit.labs.overthewire.org
	cvX2JJa4CFALtqS87jk27qwqGhBM9plV
sort data.txt | uniq -u

#uniq -u compares each line to an adjacent lines and outputs the line if it is locally unique (compared to adjacent lines)

#To ensure that the line is globally unique, we run the sort command and pipe the output into uniq

</pre>
### Level 9
<pre>
ssh -p 2220 bandit9@bandit.labs.overthewire.org
	UsvVyFSfZZWbi6wgC7dAFyFuR6jQQUhR

strings data.txt | grep '^=\+'

# Finding all ASCII strings in data.txt, we pipe that into a grep search utilising regular expression.
# '^=\+' indicatest that the line should start wtih one or more "=" characters 
# {https://www.gnu.org/software/findutils/manual/html_node/find_html/grep-regular-expression-syntax.html}


</pre>
### Level 10
<pre>
ssh -p 2220 bandit10@bandit.labs.overthewire.org
	truKLdjsbJ5g7yyJ2X2R0o3a5HQJFuLk

base64 -d data.txt 
# Decodes the base64 file and prints the output

#Some notes on base64: it is an encoding scheme that encodes binary to ACSII wehre each each base 64 digit represents 6 bits of data (since 2^6 == 64). When used on text, the chars are first converted into octets and bits before being base64 encoded {https://en.wikipedia.org/wiki/Base64#Examples}

</pre>
### Level 11
<pre>
ssh -p 2220 bandit11@bandit.labs.overthewire.org
	IFukwKGsFW8MOq3IRFqrxE1hxTNEbUPR

alias rot13="tr 'A-Za-z' 'N-ZA-Mn-za-m'"
# Define a function rot13 to perform the decryption
# A to Z is mapped to N-Z followed by A-M, the rot13 formula

cat data.txt  | rot13
# Pipe the input into the function and read the decrypted message

</pre>
### Level 12
<pre>
ssh -p 2220 bandit12@bandit.labs.overthewire.org
	5Te8Y4drgCRfCx8ugdwuEX8KFC6k2EUu

# Set up work envt
mkdir /tmp/brandontang
cp data.txt /tmp/brandontang
cd /tmp/brandontang

# Revert Hex Dump
cat data.txt
xxd -r data.txt reverted

# Recursively Unzip the files; start by finding out what type of file it is.
file reverted

# Choose unzip method
gunzip filename.gz
bzip2 -d filename.bz2
tar -xvf filename.bin

# Repeat above until ASCII file is obtained
# Read off password
cat data8

</pre>
### Level 13
ssh -p 2220 bandit13@bandit.labs.overthewire.org
	8ZjyCRiBWFYkneahHwxCv3wb2a1ORpYL

ssh -i sshkey.private bandit14@localhost
# Simply use the private key to login to the bandit 14 account

cat /etc/bandit_pass/bandit14

</pre>
### Level 14
ssh -p 2220 bandit14@bandit.labs.overthewire.org
	4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e

telnet localhost 30000
# use telnet to connect to the host <localhost> on port <30000>
	4wcYUJFw0k0XLShlDzztnTBHiqxU3b3e #enter password

</pre>
### Level 15
ssh -p 2220 bandit15@bandit.labs.overthewire.org
	BfMYroe26WYalil77FoDi9qh59eK5xNr

# Connect to localhost at port 30001 with SSL
# open an SSL connection to localhost port 30001 and print the ssl certificate used by the service
openssl s_client -connect localhost:30001
	BfMYroe26WYalil77FoDi9qh59eK5xNr #enter password

</pre>
### Level 16
ssh -p 2220 bandit16@bandit.labs.overthewire.org
	cluFn7wTiGryunymYOu4RcffSxQluehd

nmap -sV -p 31000-32000 localhost # Use Nmap to perform a service scan on ports 31000-32000

openssl s_client -connect localhost:31790 # Connect to port 31790
	cluFn7wTiGryunymYOu4RcffSxQluehd


# Output Credentials
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----



# Create a new temp directory and create a credentials file. Use it to ssh into the next </pre>
### Level
mkdir /tmp/somename
cd /tmp/somename

echo "-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAvmOkuifmMg6HL2YPIOjon6iWfbp7c3jx34YkYWqUH57SUdyJ
imZzeyGC0gtZPGujUSxiJSWI/oTqexh+cAMTSMlOJf7+BrJObArnxd9Y7YT2bRPQ
Ja6Lzb558YW3FZl87ORiO+rW4LCDCNd2lUvLE/GL2GWyuKN0K5iCd5TbtJzEkQTu
DSt2mcNn4rhAL+JFr56o4T6z8WWAW18BR6yGrMq7Q/kALHYW3OekePQAzL0VUYbW
JGTi65CxbCnzc/w4+mqQyvmzpWtMAzJTzAzQxNbkR2MBGySxDLrjg0LWN6sK7wNX
x0YVztz/zbIkPjfkU1jHS+9EbVNj+D1XFOJuaQIDAQABAoIBABagpxpM1aoLWfvD
KHcj10nqcoBc4oE11aFYQwik7xfW+24pRNuDE6SFthOar69jp5RlLwD1NhPx3iBl
J9nOM8OJ0VToum43UOS8YxF8WwhXriYGnc1sskbwpXOUDc9uX4+UESzH22P29ovd
d8WErY0gPxun8pbJLmxkAtWNhpMvfe0050vk9TL5wqbu9AlbssgTcCXkMQnPw9nC
YNN6DDP2lbcBrvgT9YCNL6C+ZKufD52yOQ9qOkwFTEQpjtF4uNtJom+asvlpmS8A
vLY9r60wYSvmZhNqBUrj7lyCtXMIu1kkd4w7F77k+DjHoAXyxcUp1DGL51sOmama
+TOWWgECgYEA8JtPxP0GRJ+IQkX262jM3dEIkza8ky5moIwUqYdsx0NxHgRRhORT
8c8hAuRBb2G82so8vUHk/fur85OEfc9TncnCY2crpoqsghifKLxrLgtT+qDpfZnx
SatLdt8GfQ85yA7hnWWJ2MxF3NaeSDm75Lsm+tBbAiyc9P2jGRNtMSkCgYEAypHd
HCctNi/FwjulhttFx/rHYKhLidZDFYeiE/v45bN4yFm8x7R/b0iE7KaszX+Exdvt
SghaTdcG0Knyw1bpJVyusavPzpaJMjdJ6tcFhVAbAjm7enCIvGCSx+X3l5SiWg0A
R57hJglezIiVjv3aGwHwvlZvtszK6zV6oXFAu0ECgYAbjo46T4hyP5tJi93V5HDi
Ttiek7xRVxUl+iU7rWkGAXFpMLFteQEsRr7PJ/lemmEY5eTDAFMLy9FL2m9oQWCg
R8VdwSk8r9FGLS+9aKcV5PI/WEKlwgXinB3OhYimtiG2Cg5JCqIZFHxD6MjEGOiu
L8ktHMPvodBwNsSBULpG0QKBgBAplTfC1HOnWiMGOU3KPwYWt0O6CdTkmJOmL8Ni
blh9elyZ9FsGxsgtRBXRsqXuz7wtsQAgLHxbdLq/ZJQ7YfzOKU4ZxEnabvXnvWkU
YOdjHdSOoKvDQNWu6ucyLRAWFuISeXw9a/9p7ftpxm0TSgyvmfLF2MIAEwyzRqaM
77pBAoGAMmjmIJdjp+Ez8duyn3ieo36yrttF5NSsJLAbxFpdlc1gvtGCWW+9Cq0b
dxviW8+TFVEBl1O4f7HVm6EpTscdDxU+bCXWkfjuRb7Dy9GOtt9JPsX8MBTakzh3
vBgsyi/sN3RqRBcGU40fOoZyfAMT8s1m/uYv52O6IgeuZ/ujbjY=
-----END RSA PRIVATE KEY-----" > bandit17key.private

ssh -i bandit17key.private bandit17@localhost
cat /etc/bandit_pass/bandit17 # Find out the actual password for bandit17

</pre>
### Level 17
ssh -p 2220 bandit17@bandit.labs.overthewire.org
	xLYVMN9WE5zQ5vHacb0sZEVqbrp7nBTn
diff passwords.new passwords.old


</pre>
### Level 18
# In this </pre>
### Level, the .bashrc logs one out immediately once an interactive session is started.
# Thus we read the password without opening an interactive bash shell
ssh -p 2220 bandit18@bandit.labs.overthewire.org "cat readme"
	kfBf3eYk5BPBRzwjqutbbfE887SVc5Yd

</pre>
### Level 19
ssh -p 2220 bandit19@bandit.labs.overthewire.org
	IueksS7Ubh8G3DCwVzrTd8rAVOwq3M5x

./bandit20-do cat /etc/bandit_pass/bandit20 # ./bandit20-do runs a command as bandit20; from there we just use it to access the bandit20 password


</pre>
### Level 20
ssh -p 2220 bandit20@bandit.labs.overthewire.org
	GbKksEFF4yrVs6il55v6gwY5aVje5f0j

tmux # create a new tmux session
printf "GbKksEFF4yrVs6il55v6gwY5aVje5f0j" | netcat -l -p 3001 # Start a port listener (daemon) on port 3001 which returns the current password to any connections that are made
[ctrl b + d] # Dettach from the tmux session

./suconnect 3001 # Connect to the port listener

tmux attach # Attach back to the tmux session
# The new password should be printed

</pre>
### Level 21
ssh -p 2220 bandit21@bandit.labs.overthewire.org
	gE269g2h3mw3pwgrj0Ha9Uoqen1c9DGr

cd /etc/cron.d
ls
cat cronjob_bandit22
'''
@reboot bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
* * * * * bandit22 /usr/bin/cronjob_bandit22.sh &> /dev/null
'''

# We can deduce that the cron job is running /usr/bin/cronjob_bandit22.sh and redirecting output to NULL.


# Now re proceed to find out what /usr/bin/cronjob_bandit22.sh does
cat /usr/bin/cronjob_bandit22.sh
'''
#!/bin/bash
chmod 644 /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
cat /etc/bandit_pass/bandit22 > /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv
'''

# The password is being written to /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv, thus we read the password from there
cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv

</pre>
### Level 22
ssh -p 2220 bandit22@bandit.labs.overthewire.org
	Yk7owGAcWjwMVRwrTesJEwB7WVOiILLI

cd /etc/cron.d
ls
cat cronjob_bandit23
cat /usr/bin/cronjob_bandit23.sh

'''
#!/bin/bash

myname=$(whoami)
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)

echo "Copying passwordfile /etc/bandit_pass/$myname to /tmp/$mytarget" #We need to find out the value of $mytarget when myname=bandit23

cat /etc/bandit_pass/$myname > /tmp/$mytarget
'''

# Simulating running the cronjob
myname="bandit23"
mytarget=$(echo I am user $myname | md5sum | cut -d ' ' -f 1)
echo $mytarget
'''8ca319486bfbbc3663ea0fbe81326349'''


# Read off the file
cat /tmp/8ca319486bfbbc3663ea0fbe81326349


</pre>
### Level 23
ssh -p 2220 bandit23@bandit.labs.overthewire.org
	jc1udXuA1tiHqjIsL8yaapX5XIAI6i0n

cd /etc/cron.d
ls
cat cronjob_bandit24
cat /usr/bin/cronjob_bandit24.sh 
cd /var/spool/bandit24

# We see that the script runs all scripts within /var/spool/bandit24 as bandit24
# thus we need to write a script to extract the password from /etc/bandit_pass/bandit24

# Use nano to write the following script to /var/spool/bandit24/script.sh
# Note that there is no point printing debugging statements because all std output is redirected to Null by the cron job
"""
#!/bin/bash
cat /etc/bandit_pass/bandit24 > bandit24pass 
"""

chmod +x script.sh
# Wait a while for the cronjob to run (~ 1 min or so), keep checking if bandit24pass is generated yet
cat bandit24pass


</pre>
### Level 24
ssh -p 2220 bandit24@bandit.labs.overthewire.org
	UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ


# Create a tmp directory and cd there to do all the work
# Create a bash script to bruteforce the daemon (saved as bandit.sh)
"""
#!/bin/bash
for i in {1000..10000}
do
	echo $i
	printf "UoMYTrfrBFHyQXmg6gzctqAwOmw1IohZ $i\n" | netcat localhost 30002
done
"""

chmod +x bandit.sh # Make bandit.sh executable

# Pipe the file into the daemon and write output to the "output" file
# Note that letting the daemon write to stdout resulted in a time out error (for me)
./bandit.sh | netcat localhost 30002 > output 

cat output
# the password is on the last line


</pre>
### Level 25 --> 27 
ssh -p 2220 bandit25@bandit.labs.overthewire.org
	uNG9O58gUE7snukf3bvZ0rxhtnjzSGzG

ssh -i bandit26.sshkey bandit26@localhost
cat /etc/passwd
cat /usr/bin/showtext
'''
#!/bin/sh

export TERM=linux

more ~/text.txt
exit 0
'''

# (i failed to do this myself) 
# Make the terminal small and run (this actually hard)
ssh -i bandit26.sshkey bandit26@localhost

# press v to get a vim editor


# Perform a shell escape (i believe the space is impt)
# ":! /bin/bash"


# Get </pre>
### Level 27 password
./bandit27-do cat /etc/bandit_pass/bandit27


</pre>
### Level 27
ssh -p 2220 bandit27@bandit.labs.overthewire.org
	3ba3118a22e93127a4ed485be72ef5ea

# Create tmp working envt
mkdir /tmp/brandontang89
cd /tmp/brandontang89

# Clone the git repo
git clone ssh://bandit27-git@localhost/home/bandit27-git/repo

# Read the password
cat /repo/README


</pre>
### Level 28
ssh -p 2220 bandit28@bandit.labs.overthewire.org
	0ef186ac70e04ea33b4c1853d2526fa2

# Create tmp working envt
mkdir /tmp/brandontang1
cd /tmp/brandontang1

# Clone the git repo
git clone ssh://bandit28-git@localhost/home/bandit28-git/repo
cd repo

# Analyse the files
cat README.md
'''
# Bandit Notes
Some notes for </pre>
### Level29 of bandit.

## credentials

- username: bandit29
- password: xxxxxxxxxx
'''
 
 # The password has been hidden, but maybe it was in plain text in an older version of the file
git log --all --full-history -- * # Displays all commits
'''
commit 073c27c130e6ee407e12faad1dd3848a110c4f95
Author: Morla Porla <morla@overthewire.org>
Date:   Tue Oct 16 14:00:39 2018 +0200

    fix info leak

commit 186a1038cc54d1358d42d468cdc8e3cc28a93fcb
Author: Morla Porla <morla@overthewire.org>
Date:   Tue Oct 16 14:00:39 2018 +0200

    add missing data

commit b67405defc6ef44210c53345fc953e6a21338cc7
Author: Ben Dover <noone@overthewire.org>
Date:   Tue Oct 16 14:00:39 2018 +0200

    initial commit of README.md
'''

# We see that there are several different versions of the file, trying the second commit yields the flag
git show 186a1038cc54d1358d42d468cdc8e3cc28a93fcb:README.md 
'''
# Bandit Notes
Some notes for </pre>
### Level29 of bandit.

## credentials

- username: bandit29
- password: bbc96594b4e001778eee9975372716b2
'''

</pre>
### Level 29: # Basically a repeat of the previous </pre>
### Level
ssh -p 2220 bandit29@bandit.labs.overthewire.org
	bbc96594b4e001778eee9975372716b2

# Set up work envt
mkdir /tmp/brandontang2
cd /tmp/brandontang2
git clone ssh://bandit29-git@localhost/home/bandit29-git/repo
	bbc96594b4e001778eee9975372716b2
cd repo

# Honestly do the exact same thing as above
git log --all --full-history -- * # Displays all commits
git show 9b19e7d8c1aadf4edcc5b15ba8107329ad6c5650:README.md
'''
# Bandit Notes
Some notes for bandit30 of bandit.

## credentials

- username: bandit30
- password: 5b90576bedb2cc04c86a9e924ce42faf
'''

</pre>
### Level 30
ssh -p 2220 bandit30@bandit.labs.overthewire.org
	5b90576bedb2cc04c86a9e924ce42faf


# Set up work envt
mkdir /tmp/brandontang3
cd /tmp/brandontang3
git clone ssh://bandit30-git@localhost/home/bandit30-git/repo
	5b90576bedb2cc04c86a9e924ce42faf
cd repo

cd .git

cat packed-refs
'''
# pack-refs with: peeled fully-peeled
3aa4c239f729b07deb99a52f125893e162daac9e refs/remotes/origin/master
f17132340e8ee6c159e0a4a6bc6f80e1da3b1aea refs/tags/secret
'''
# We see theres some tag; the following command reveals it to be a "blob"
git cat-file -t f17132340e8ee6c159e0a4a6bc6f80e1da3b1aea

# We then print the blob contents and read the password
git cat-file -p f17132340e8ee6c159e0a4a6bc6f80e1da3b1aea > secret.txt
cat secret.txt

</pre>
### Level 31
ssh -p 2220 bandit31@bandit.labs.overthewire.org
	47e603bb428404d265f59c42920d81e5

# Set up work envt
mkdir /tmp/brandontang4
cd /tmp/brandontang4
git clone ssh://bandit31-git@localhost/home/bandit31-git/repo
cd repo
	
cat REAMD.md
'''
This time your task is to push a file to the remote repository.

Details
<pre>
    File name: key.txt
    Content: 'May I come in?'
    Branch: master
'''

# Here we simply create the file they requested, the push it to the remote repo
echo 'May I come in?' > key.txt
git add key.txt -f
git commit -m "added key"
git push origin master
	47e603bb428404d265f59c42920d81e5

'''
remote: ### Attempting to validate files... ####
remote
<pre>
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote
<pre>
remote: Well done! Here is the password for the next </pre>
### Level
<pre>
remote: 56a9bf19c63d650ce78e6ec0354ee45e
remote
<pre>
remote: .oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.oOo.
remote
<pre>
'''

</pre>
### Level 32
ssh -p 2220 bandit32@bandit.labs.overthewire.org
	56a9bf19c63d650ce78e6ec0354ee45e

# Quick testing and analysis reveals that all the commands keyed into the shell are capitalised and thus rendered ineffective
# To deal with this, we try out some "bash special variables"

$0
# returns the first word; that is the command name (in this case sh)
# running $0 will thus spawn a sh shell where we can read off the final password

cat /etc/bandit_pass/bandit33
'''c9c3199ddf4121b10cf581a98d51caee'''

</pre>
### Level 33 [Victory </pre>
### Level]
ssh -p 2220 bandit33@bandit.labs.overthewire.org
	c9c3199ddf4121b10cf581a98d51caee

ls
cat README.txt
'''
Congratulations on solving the last </pre>
### Level of this game!

At this moment, there are no more </pre>
### Levels to play in this game. However, we are constantly working
on new </pre>
### Levels and will most likely expand this game with more </pre>
### Levels soon.
Keep an eye out for an announcement on our usual communication channels!
In the meantime, you could play some of our other wargames.

If you have an idea for an awesome new </pre>
### Level, please let us know!
'''
