# SimplePySSH
Allows for remote execution of simple commands via SSH using only built-in Python modules.
Based on code from a blog post by Paul Mikesell (http://blog.clustrix.com/2012/01/31/scripting-ssh-with-python/)

**If you are not constrained by the need to only use built-in modules you should use one of the better 
implementations of SSH for Python such as Paramiko or PySSH2**

## Examples

If you are importing the module it can be used as follows:
```
import SimplePySSH

x = SSH("x.x.x.x", "someuser", somepassword"")
result1 = x.cmd("ifconfig")
result2 = x.cmd("whoami")
```

Running the module as a standalone script results in the following:
```
$ ./SimplePySSH.py 
Enter ip address of target machine: NotAnIpAddress
NotAnIpAddress does not appear to be a valid ip address.
Enter ip address of target machine: 127.0.0.1
Enter target username: SomeUser
Password: 
Enter the command you wish to run on remote machine: whoami

SomeUser

$
```
