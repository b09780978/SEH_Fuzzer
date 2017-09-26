from PE import *
from util import *
from Gadget import *
import struct

import sys
import platform
import os

from pydbg import *
from pydbg.defines import *

import cPickle
import random

PICKLE_GADGET = "fsws.pkl"

exe_path = "D:\\testPoc\\Easy File Sharing Web Server\\fsws.exe"

import threading
import time

win7After = True if platform.release() in ["6", "7", "8", "vista", "win7", "2008server", "win8", "win8.1", "win10"] else False

# Get module list without system module.
def getModuleList(dbg, exe_path):
	system_dlls = dbg.system_dlls
	file_prefix = "\\".join(exe_path.split("\\")[1:-1])
	disk = exe_path[0:2]
	ModulesList = [exe_path]

	for dll in system_dlls:
		if file_prefix in dll.path:
			ModulesList.append(disk + dll.path)

	return ModulesList

# Get gadget by no protect module, IAT and wriatable address.
def getRopGadgetAndIATAndWriteAddress(dbg, ModulesList):
	# Get all usable gadgets.
	collect_gadgets = {}
	IAT = {}
	wriatableAddress = {}

	for module in ModulesList:
		pe = PE(module)
		image_top = pe.Base + pe.BaseSize
		if pe.Base>0:
			peOffset = struct.unpack("<L", dbg.read(pe.Base+0x3c, 4))[0]
			base = pe.Base + peOffset
			safeseh_offset = [0x5f, 0x5f, 0x5e]
			safeseh_flag = [0x4, 0x4, 0x400]
			os_index = 2 if win7After else 0
			module_flag = struct.unpack("<H", dbg.read(base+safeseh_offset[os_index], 2))[0]
			# check safeSEH
			safeSEH = True if module_flag & safeseh_flag[os_index] else False
			# check ASLR
			ASLR = True if module_flag & 0x0040 else False
			# check NX
			NX = True if module_flag & 0x0100 else False
		
		if (not safeSEH) and (not ASLR):
			module_name = module.lower()
			Rebase = True
			for mod in dbg.enumerate_modules():
				if module_name.endswith(mod[0].lower()) and mod[1] == pe.Base:
					Rebase = False
					break
			if not Rebase:
				print "[+] Module %s add." % module
				module_gadget = Gadget(pe)
				classify_gadget(module_gadget.retGadgets, module_gadget.jmpGadgets, collect_gadgets)
				IAT.update( { module : pe.IAT } )
				for section in pe.DataSections:
					for test in xrange(5):
						vaddr = section["vaddr"] + random.randint(0,section["size"])
						if gadget_filter(vaddr):
							wriatableAddress.update( { vaddr : module } )
							break
	return collect_gadgets, IAT, wriatableAddress

class Fuzzer(object):
	def __init__(self, exe_path):
		self.exe_path = exe_path
		self.pid = None
		self.dbg = None
		self.running = True
		self.pe = PE(exe_path)
		self.gadgets = Gadget(self.pe)
		
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
			self.ModulesList = getModuleList(self.dbg, self.exe_path)
			'''
			for l in self.ModulesList:
				print l
			'''
			print "[+] Get no protect modules."
			global PICKLE_GADGET
			PICKLE_GADGET = self.exe_path.split("\\")[-1].replace(".exe", ".pkl")

			# if first analysis.
			if not os.path.isfile(PICKLE_GADGET):
				with open(PICKLE_GADGET, "wb") as local_file:
					collect_gadgets, IAT, wriatableAddress = getRopGadgetAndIATAndWriteAddress(self.dbg, self.ModulesList)
					cPickle.dump(collect_gadgets, local_file)
					cPickle.dump(IAT, local_file)
					cPickle.dump(wriatableAddress, local_file)
			
			else:
				with open(PICKLE_GADGET, "rb") as local_file:
					collect_gadgets = cPickle.load(local_file)
					IAT = cPickle.load(local_file)
					wriatableAddress = cPickle.load(local_file)
			

			print "[+] Get Rop Gadget."
			
			# cPickle.dump()
			rop_chain = generate_ropchain(collect_gadgets, IAT, wriatableAddress)
			print
			print "[+] ROP Chain"
			print "ropchain = [ "
			for a,b in rop_chain:
				print '   ',hex(a), ", #", b
			print "]"
			print

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
		
exe_path = "D:\\testPoc\\Easy File Sharing Web Server\\fsws.exe"
Fuzzer(exe_path)