# paramiko

If you use the `paramiko` libary for Python, then you'll have to manually load the public key like this:

```python
import paramiko

private_key = paramiko.ECDSAKey(filename='/home/username/.ssh/opkssh_server_group1')
private_key.load_certificate('/home/username/.ssh/opkssh_server_group1-cert.pub')

sshcon  = paramiko.SSHClient()
sshcon.set_missing_host_key_policy(paramiko.AutoAddPolicy())
sshcon.connect('192.168.10.10', username='ubuntu', pkey=private_key)
```
