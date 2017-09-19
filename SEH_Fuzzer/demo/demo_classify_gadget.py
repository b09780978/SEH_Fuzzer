from PE import *
from util import *
from Gadget import *

exe_path = "D:\\testPoc\\Easy File Sharing Web Server\\fsws.exe"

module_list = getModuleList(exe_path)
module_list.append(exe_path)

# Get all usable gadgets.
collect_gadgets = {}
for module in module_list:
	pe = PE(module)
	if (not pe.ASLR) and (not pe.SafeSEH) and (not pe.Rebase):
		print "[+] Module %s add." % module
		module_gadget = Gadget(pe)
		classify_gadget(module_gadget.retGadgets, module_gadget.jmpGadgets, collect_gadgets)

print

for types in collect_gadgets.keys():
	print "+" + "-"*(len(types)+2) + "+"
	print "| " + types + " |"
	print "+" + "-"*(len(types)+2) + "+"
	print
	for addr, gadget in collect_gadgets[types].items():
		print "[*] 0x%08x : %s." % (addr, gadget)
	print