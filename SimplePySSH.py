#!/usr/bin/python
#
# Allows remote execution of commands via Python using only built-in modules
# Based on code from a blog post by Paul Mikesell
# http://blog.clustrix.com/2012/01/31/scripting-ssh-with-python/

import getpass
import os
import platform
import pty
import re
import socket
import subprocess
import sys

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
    	"""Run input command on remote machine via ssh in forked child process"""
        (pid, f) = pty.fork()
        if pid == 0:
	    # if sudo command then requires pseudo-tty allocation
            if c.startswith("sudo"):
                os.execlp("/usr/bin/ssh", "ssh",
                    "-t", self.user + '@' + self.ip, c)
            # otherwise pseudo-tty not required
	    else:
                os.execlp("/usr/bin/ssh", "ssh",
                    self.user + '@' + self.ip, c)
        else:
            return (pid, f)

    def _read(self, f):
    	"""Read and return bytes from file descriptor. If byte string starts with "Connection to" return empty string."""
        x = ""
        try:
            x = os.read(f, 1024)

        except Exception, e:
            # this always fails with io error
            pass
        # replace "Connection to x.x.x.x closed" lines from pseudo-tty allocated ssh sessions w/ empty string
        return x if not x.strip().startswith("Connection to") else ''

    def ssh_results(self, pid, f):
    	"""Read and return output from file descriptor while waiting for completion of child process.
    	Also responds to prompts for passwords and host authenticity."""
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
            got = self._read(f)
        m = re.search("Warning:", got)
        if m:
            os.write(f, '\n')
            tmp = self._read(f)
            tmp += self._read(f)
            got = tmp
	# check for passwd request
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
    	"""Run input command on remote machine via ssh and return results"""
        (pid, f) = self.run_cmd(c)
        return self.ssh_results(pid, f)

    def set_key_auth(self, user, option):
    	"""Add or remove key-based authentication for specified user to remote machine"""
        RemoteOS = self.cmd("uname").strip()
        # directory for authorized_keys file depends on OS
	# only handles OS X, Linux for now
	if RemoteOS == 'Darwin':
            ssh_dir = "/private/var/root/.ssh"
        elif RemoteOS == 'Linux':
            ssh_dir = "/root/.ssh"
        else:
            raise ValueError('Unsupported OS on remote machine: %s' % RemoteOS)
        auth_keys = ssh_dir + "/authorized_keys"
        pub_key = ssh_keygen(user)
        contents = self.get_auth_keys(ssh_dir, auth_keys)
	# add if add option specified and public key not in contents
        if option == 'add' and not pub_key in contents:
            self.write_auth_key(pub_key, auth_keys)
	# remove if remove option specified and public key in contents
        if option == 'remove' and pub_key in contents:
            self.remove_auth_key(pub_key, contents, auth_keys)

    def get_auth_keys(self, ssh_dir, auth_keys):
    	"""Return remote machines authorized public keys"""
        cmd = "sudo ls %s" % auth_keys
        out = self.cmd(cmd)
        # if file doesn't exist then make file (and parent directory if needed)
        m = re.search("such file or directory", out)
        if m:
            cmd = "sudo mkdir -p %s" % ssh_dir
            self.cmd(cmd)
            cmd = "sudo touch %s" % auth_keys
            self.cmd(cmd)
        cmd = "sudo cat %s" % auth_keys
        return self.cmd(cmd)

    def write_auth_key(self, pub_key, auth_keys):
    	"""Append public key to remote machines authorized public keys"""
        cmd = "sudo echo \"%s\" | sudo tee -a %s" % (pub_key, auth_keys)
        self.cmd(cmd)

    def remove_auth_key(self, pub_key, contents, auth_keys):
    	"""Remove all instances of pub_key from remote machines authorized public keys"""
        # Remove carriage returns, split contents on newline, and filter out empty string and string matching pub_key
        contents = [key for key in contents.replace('\r', '').split('\n') if key not in ('', pub_key)]
        # Join the filter strings on newlines into a new string
        contents = '\n'.join(contents)
        # Overwrite the authorized_keys file of the remote machine with the new filter contents string
        cmd = "sudo echo \"%s\" | sudo tee %s" % (contents, auth_keys)
        self.cmd(cmd)

def ssh_cmd(ip, user, passwd, cmd):
    """Create an SSH session using provided target ip and credentials, run cmd, and return output"""
    s = SSH(ip, user, passwd)
    return s.cmd(cmd)

def valid_ip(address):
    """Return True if address is a valid ip address, False otherwise."""
    try: 
        socket.inet_aton(address)
    except socket.error: 
        return False
    else:
        return address.count('.') == 3

def get_ip():
    """Prompt user to input ip address. Will continue to prompt until valid ip is entered."""
    ip = raw_input("Enter ip address of target machine: ")
    while not valid_ip(ip):
        print "%s does not appear to be a valid ip address." % ip
        ip = raw_input("Enter ip address of target machine: ")
    return ip

def get_local_user():
    """Return SUDO_USER env variable if set, otherwise return USER env variable
    Used to find out which user called script when run using sudo user."""
    if os.environ.has_key('SUDO_USER'):
        user = os.environ['SUDO_USER']
    else:
        user = os.environ['USER']
    return user

def ssh_keygen(user):
    """Generate and return public key from id_rsa. If id_rsa doesn't exist then it is generated.
    Raises ValueError if OS is not Mac or Linux."""
    LocalOS = platform.system()
    if LocalOS == 'Darwin':
        homedir = "/Users/"
    elif LocalOS == 'Linux':
        homedir = "/home/"
    # Only supports OS X and Linux currently
    else:
        raise ValueError('Unsupported OS on local machine: %s' % LocalOS)
    id_rsa = homedir + "%s/.ssh/id_rsa" % user
    if os.path.isfile(id_rsa):
        pub_key = subprocess.check_output(["ssh-keygen", "-y", "-f", id_rsa]).strip()
    else:
        pub_key = subprocess.check_output(["ssh-keygen", "-t", "rsa", "-N", '', "-f", id_rsa]).strip()
    return pub_key

def get_bool_yes_no(prompt):
    """Prompts user with input prompt. Loops until user inputs either yes or no. 
    Returns True if input is yes, False if no."""
    yes = set(['yes','y', 'ye', ''])
    no = set(['no','n'])
    choice = raw_input(prompt).lower()
    if choice in yes:
        return True
    elif choice in no:
        return False
    else:
        print "Please enter yes or no"
        get_yes_no(prompt)


if __name__ == "__main__":
    # Get username of calling user if run as root
    local_user = get_local_user()
    # Get user input
    ip = get_ip()
    user = raw_input("Enter target username: ")
    passwd = getpass.getpass(prompt="Enter the password for the target user: ")
    # Create SSH session
    ssh = SSH(ip, user, passwd)
    # Optionally set key-based authentication
    key_auth = get_bool_yes_no(prompt="Configure key-based authentication with remote machine? (y/n): ")
    if key_auth:
        ssh.set_key_auth(local_user, "add")
    # Loop through prompting for commands to run until exit() is called
    # If input commnad is empty string then skips
    while True:
        cmd = raw_input("Enter the command you wish to run on remote machine: ")
        if cmd == "exit()":
            break
        elif cmd == '':
            continue
        result = ssh.cmd(cmd)
        print result
    # Optionally remove key-based authentication if it has been configured.
    rm_key_auth = get_bool_yes_no(prompt="Remove key-based authentication with remote machine? (y/n): ")
    if rm_key_auth:
        ssh.set_key_auth(local_user, "remove")

