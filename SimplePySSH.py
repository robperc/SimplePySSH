#!/usr/bin/python
#
# Allows remote execution of commands via Python using only built-in modules
# Based on code from a blog post by Paul Mikesell
# http://blog.clustrix.com/2012/01/31/scripting-ssh-with-python/

import argparse
import getpass
import os
import platform
import pty
import re
import signal
import socket
import stat
import subprocess
import sys

class SSHError(Exception):
	""" Handles exceptions thrown by SSH class.

	Attributes:
		value (str): Human readable string describing the exception.

	"""
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

class SSH:
	""" Holds the information needed to send shell commands to remote machines via SSH and receive output.

	Attributes:
		ip (str): IP address of remote host.
		user (str): Username to use when connecting to remote host.
		passwd (str): Password of remote user.

	"""

	def __init__(self, ip, user, passwd):
		self.ip = ip
		self.passwd = passwd
		self.user = user

	def run_cmd(self, c):
		"""Run input command on remote machine via ssh in forked child process.

		Args:
			c (str): the shell command to run on the remote host.
		Returns:
			None if pid == 0.
			pid and file descriptor of forked shell process otherwise.
		"""
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
		"""Read and return bytes from file descriptor.
		   Filters bytes to remove strings that begin with "Connection to"

		Args:
			f (int): file descriptor to read from.
		Returns:
			First 1024 bytes read from f after filtering.
		"""
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
		Also responds to prompts for passwords and host authenticity.

		Args:
			pid (int): pid of child process
			f (int): file descriptor of child process.
		Returns:
			Output read from file descriptor of child process until it exits.
		Raises:
			SSHError:   if there is no response from the target IP address
						if SSH connection refused by remote host (IE: not enabled)
						if remote username or password is invalid
		"""
		output = ""
		got = self._read(f)
		# Raise exception if operation times out due to no response from remote host
		m = re.search("Operation timed out", got)
		if m:
			raise SSHError("No response from IP address %s." % self.ip)
		# Raise exception if connection is refused by remote host
		m = re.search("Connection refused", got)
		if m:
			raise SSHError("SSH connection refused by remote host.")
		# If prompted trust host authenticity
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
		# Warnings are for dorks, write past them with newline
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
					raise SSHError("Invalid username or passwd")
				# passwd was accepted
				got = tmp
		# Append command output until it is empty
		while got and len(got) > 0:
			output += got
			got = self._read(f)
		os.waitpid(pid, 0)
		os.close(f)
		return output

	def cmd(self, c):
		"""Read and return ouput from command run on remote host via ssh.

		Args:
			c (str): the shell command to run on the remote host.
		Returns:
			Full output of command run on remote host.
		"""
		(pid, f) = self.run_cmd(c)
		return self.ssh_results(pid, f)

	def push_dir(self, src, dst):
		(pid, f) = pty.fork()
		if pid == 0:
			os.execlp("/usr/bin/scp", "scp", "-r", src,
					  self.user + '@' + self.ip + ':' + dst)
		else:
			return (pid, f)

	def push_file(self, src, dst):
		(pid, f) = pty.fork()
		if pid == 0:
			os.execlp("/usr/bin/scp", "scp", src,
					  self.user + '@' + self.ip + ':' + dst)
		else:
			return (pid, f)

	def set_key_auth(self, user, option):
		"""Add or remove key-based authentication for specified user to remote machine.

		Args:
			user (str): the local user to set key-based authorization to the remote host with.
			option (str): option to add or remove key-based auth with remote host. One of ['add', 'remove'].
		Raises:
			ValueError: if OS is not supported.
		"""
		RemoteOS = self.cmd("uname").strip()
		# Directory for authorized_keys file depends on OS
		# Only handles OS X, Linux for now
		if RemoteOS == 'Darwin':
			ssh_dir = "/private/var/root/.ssh"
		elif RemoteOS == 'Linux':
			ssh_dir = "/root/.ssh"
		# Throw exception if OS not supported
		else:
			raise SSHError('Unsupported OS on remote machine: %s' % RemoteOS)
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
		"""Return authorized public keys of remote host.
		If the file doesn't exist it is created.

		Args:
			ssh_dir (str): the full path to the root '.ssh' directory of the remote host.
			auth_keys (str): the full path to the root authorized_keys file of the remote host.
		Returns:
			Contents of the authorized_keys file of remote host
		"""
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
		"""Append public key to remote machines authorized public keys.

		Args:
			pub_key (str): the public key to write to authorized_keys file of remote host.
			auth_keys (str): the full path to the root authorized_keys file of the remote host.
		"""
		cmd = "sudo echo \"%s\" | sudo tee -a %s" % (pub_key, auth_keys)
		self.cmd(cmd)

	def remove_auth_key(self, pub_key, contents, auth_keys):
		"""Remove all instances of pub_key from remote machines authorized public keys.

		Args:
			pub_key (str): the public key to remove from authorized_keys file of remote host.
			contents (str): string contents of the authorized_keys file of remote host.
			auth_keys (str): the full path to the root authorized_keys file of the remote host.
		"""
		# Remove carriage returns, split contents on newline, and filter out empty string and string matching pub_key
		contents = [key for key in contents.replace('\r', '').split('\n') if key not in ('', pub_key)]
		# Join the filter strings on newlines into a new string
		contents = '\n'.join(contents)
		# Overwrite the authorized_keys file of the remote machine with the new filter contents string
		cmd = "sudo echo \"%s\" | sudo tee %s" % (contents, auth_keys)
		self.cmd(cmd)

def ssh_cmd(ip, user, passwd, cmd):
	"""Create an SSH session using provided target ip and credentials, run cmd, and return output."""
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
	# If called as sudo this will be set to the user who sudo'd
	if os.environ.has_key('SUDO_USER'):
		user = os.environ['SUDO_USER']
	# Otherwise just return the invoking user's name
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
	yes = set(['yes','y', 'ye'])
	no = set(['no','n'])
	choice = raw_input(prompt).lower()
	if choice in yes:
		return True
	elif choice in no:
		return False
	else:
		print "Please enter yes or no"
		return get_bool_yes_no(prompt)

def handler(signum, frame):
	"""Handles signals gracefully."""
	print
	sys.exit(0)

if __name__ == "__main__":
	# Configure graceful handler for signal interrupts
	signal.signal(signal.SIGINT, handler)
	# Parse args if there are any
	parser = argparse.ArgumentParser(
		description='Command line tool for running shell commands on remote hosts via SSH and capturing the output.',
	)
	parser.add_argument('--ip', metavar='RemoteIP', type=str, nargs=1, 
		help='IP address of remote host.',
	)
	parser.add_argument('--user', metavar='RemoteUser', type=str, nargs=1, 
		help='Username of user to SSH into remote host as.',
	)
	args = parser.parse_args()
	# Get username of calling user if run as root
	local_user = get_local_user()
	# Get user input
	ip = args.ip[0] if args.ip else get_ip() # If there is a cmd line arg use it otherwise prompt user
	user = args.user[0] if args.user else raw_input("Enter target username: ") # If there is a cmd line arg use it otherwise prompt user
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

