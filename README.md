# SimplePySSH
Allows for remote execution of simple commands via SSH using only built-in Python modules.
Based on code from a blog post by Paul Mikesell (http://blog.clustrix.com/2012/01/31/scripting-ssh-with-python/)

**If you are not constrained by the need to only use built-in modules you should use one of the better 
implementations of SSH for Python such as Paramiko or PySSH2**

## Examples

If you are importing the module it can be used as follows:
```
import SimplePySSH

x = SSH("192.168.0.100", "SomeUser", "SomePassword")
result1 = x.cmd("ifconfig")
result2 = x.cmd("whoami")
```

Running the module as a standalone script results in the following:
```
$ ./SimplePySSH.py 
Enter ip address of target machine: NotAnIpAddress
NotAnIpAddress does not appear to be a valid ip address.
Enter ip address of target machine: 192.168.0.100
Enter target username: SomeUser
Enter the password for the target user:
Configure ssh-key authorization with remote machine? (y/n): y 
Enter the command you wish to run on remote machine: ifconfig | grep 192.168.0.100

	inet 192.168.0.100 netmask 0xffffff00 broadcast 192.168.0.255

Enter the command you wish to run on remote machine: whoami

	SomeUser

Enter the command you wish to run on remote machine: sudo whoami

	root

Enter the command you wish to run on remote machine: echo $TERM

	dumb

Enter the command you wish to run on remote machine: exit()
Remove ssh-key authorization with remote machine? (y/n): n
$
```
Now that you have added your public key to the remote machines authorized_keys you can ssh in 
without the need for a password (although the prompt for the password will still appear).
```
$ ./SimplePySSH.py
Enter ip address of target machine: 192.168.0.100
Enter target username: root
Configure ssh-key authorization with remote machine? (y/n): n
Enter the command you wish to run on remote machine: whoami

	root

Enter the command you wish to run on remote machine: exit()
Remove ssh-key authorization with remote machine? (y/n): y
$
```
Typing 'y' to the 'Remove ssh-key authorization...' prompt will remove all instances of your public key
from the remote machines authorized_hosts.
