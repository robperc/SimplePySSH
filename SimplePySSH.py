#!/usr/bin/python
#
# Allows remote execution of commands via Python using only built-in modules
# Based on code from a blog post by Paul Mikesell
# http://blog.clustrix.com/2012/01/31/scripting-ssh-with-python/

import getpass
import os
import pty
import re
import sys
import socket

class SSHError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)

class SSH: 
    def __init__(self, ip, user, passwd):
        self.ip = ip
        self.passwd = passwd
        self.user = user

    def run_cmd(self, c):
        (pid, f) = pty.fork()
        if pid == 0:
            os.execlp("/usr/bin/ssh", "ssh",
                "-t", self.user + '@' + self.ip, c)
        else:
            return (pid, f)

    def _read(self, f):
        x = ""
        try:
            x = os.read(f, 1024)
        except Exception, e:
            # this always fails with io error
            pass
        return x

    def ssh_results(self, pid, f):
        output = ""
        got = self._read(f)
        m = re.search("authenticity of host", got)
        if m:
            os.write(f, 'yes\n') 
            # Read until we get ack
            while True:
                got = self._read(f)
                m = re.search("Permanently added", got)
                if m:
                    break
            got = self._read(f)         # check for passwd request
        m = re.search("Warning:", got)
        if m:
            os.write(f, '\n')
            tmp = self._read(f)
            tmp += self._read(f)
            got = tmp
        for tries in range(3):
            m = re.search("assword:", got)
            if m:
                # send passwd
                os.write(f, self.passwd + '\n')
                # read two lines
                tmp = self._read(f)
                tmp += self._read(f)
                m = re.search("Permission denied", tmp)
                if m:
                    raise Exception("Invalid username or passwd")
                # passwd was accepted
                got = tmp
        while got and len(got) > 0:
            output += got
            got = self._read(f)
        os.waitpid(pid, 0)
        os.close(f)
        return output

    def cmd(self, c):
        (pid, f) = self.run_cmd(c)
        return self.ssh_results(pid, f)

def ssh_cmd(ip, user, passwd, cmd):
    s = SSH(ip, user, passwd)
    return s.cmd(cmd)

def valid_ip(address):
    try: 
        socket.inet_aton(address)
    except socket.error: 
        return False
    else:
        return address.count('.') == 3

def get_ip():
    ip = raw_input("Enter ip address of target machine: ")
    while not valid_ip(ip):
        print "%s does not appear to be a valid ip address." % ip
        ip = raw_input("Enter ip address of target machine: ")
    return ip

# def ssh_keygen():
#     id_rsa = "/Users/%s/.ssh/id_rsa" % user
#     if os.path.isfile(id_rsa):
#         # gen key from pre-existing id_rsa
#     else:
#         # need to gen id_rsa priv key


if __name__ == "__main__":
    ip = get_ip()
    user = raw_input("Enter target username: ")
    passwd = getpass.getpass(prompt="Enter the password for the target user: ")
    ssh = SSH(ip, user, passwd)
    while True:
        cmd = raw_input("Enter the command you wish to run on remote machine: ")
        if cmd == "exit()":
            break
        result = ssh.cmd(cmd)
        print result
