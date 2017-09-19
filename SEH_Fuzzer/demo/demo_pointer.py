from PE import *
from util import *
from Gadget import *

exe_path = "D:\\testPoc\\Easy File Sharing Web Server\\fsws.exe"

module_list = getModuleList(exe_path)
module_list.append(exe_path)

import random

IAT = {}
writableAddress = {}
print
for module in module_list:
	print module
	pe = PE(module)
	IAT.update( { module: pe.IAT } )
	for section in pe.DataSections:
		vaddr = section["vaddr"] + random.randint(0, section["size"])
		for test in xrange(5):
			if gadget_filter(vaddr):
				writableAddress.update( { vaddr : module } )
				break

print "[+] IAT"
print
for entry in IAT.keys():
	print "[+] Module %s" % entry
	for func, vaddr in IAT[entry].items():
		if gadget_filter(vaddr):
			print "[*]%-30s : 0x%08x." % (func, vaddr)
	print

print
print "[+] writable Address"
print
for vaddr, module in writableAddress.items():
	print "[*]%-10s : 0x%08x" % (module, vaddr)