# SimplePySSH
Module for executing and reading output from simple shell commands on remote machines via SSH using only built-in modules.

Based on code from a blog post by Paul Mikesell (http://blog.clustrix.com/2012/01/31/scripting-ssh-with-python/)

**If you are not constrained by the need to only use built-in modules you should use one of the better 
implementations of SSH for Python such as Paramiko or PySSH2**

## Examples

If you are importing the module it can be used as follows:
```
import SimplePySSH

ssh = SSH("192.168.0.100", "SomeUser", "SomePassword")
# result1 === "inet 192.168.0.100 netmask 0xffffff00 broadcast 192.168.0.255"
result1 = ssh.cmd("ifconfig | grep 192.168.0.100")
# result2 === "SomeUser"
result2 = ssh.cmd("whoami")
# result3 === "root"
result3 = ssh.cmd("sudo whoami")
# write public key to authorized_keys of remote machine
ssh.set_key_auth("YourLocalUsername", "add")
# can now ssh as root without password
rootssh = SSH("192.168.0.100", "root", "")
# result4 === "root"
result4 = rootssh.cmd("whoami")
# remove all instances of public key from remote machines authorized_keys
ssh.set_key_auth("YourLocalUsername", "remove")

```

Running the module as a standalone script results in the following:
```
$ ./SimplePySSH.py 
Enter ip address of target machine: NotAnIpAddress
NotAnIpAddress does not appear to be a valid ip address.
Enter ip address of target machine: 192.168.0.100
Enter target username: SomeUser
Enter the password for the target user:
Configure key-based authentication with remote machine? (y/n): y 
Enter the command you wish to run on remote machine: ifconfig | grep 192.168.0.100

	inet 192.168.0.100 netmask 0xffffff00 broadcast 192.168.0.255

Enter the command you wish to run on remote machine: whoami

	SomeUser

Enter the command you wish to run on remote machine: sudo whoami

	root

Enter the command you wish to run on remote machine: echo $TERM

	dumb

Enter the command you wish to run on remote machine: exit()
Remove key-based authentication with remote machine? (y/n): n
$
```
Now that you have added your public key to the remote machines authorized_keys you can ssh in 
without the need for a password (although the prompt for the password will still appear).
```
$ ./SimplePySSH.py
Enter ip address of target machine: 192.168.0.100
Enter target username: root
Configure key-based authentication with remote machine? (y/n): n
Enter the command you wish to run on remote machine: whoami

	root

Enter the command you wish to run on remote machine: exit()
Remove key-based authentication with remote machine? (y/n): y
$
```
Entering 'y' at the 'Remove key-based authentication...' prompt will remove all instances of your public key
from the remote machines authorized_keys.
