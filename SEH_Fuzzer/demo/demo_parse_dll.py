import sys
import os

CURRENT_DIR = os.getcwd()
PE_DIR = "\\".join(CURRENT_DIR.split("\\")[:-1])
print "[+] Current position: %s" % (CURRENT_DIR)
print "[+] PE class position: %s" % (PE_DIR)
print

# add PE class folder
sys.path.append(PE_DIR)
from PE import *

exe = PE_DIR + "\\vuln\\ImageLoad.dll"

pe = PE(exe)

print "[+] Analysis %s." % (pe.Name)
print "[*] Format is %s." % (pe.Format)
print "[*] Type is %s." % (pe.Type)
print "[*] Arch is %s." % (pe.Arch)
print "[*] Bits is %d." % (pe.Bits)
print "[*] EntryPoint is 0x%08x." % (pe.EntryPoint)
print "[*] Rebase is", "on." if pe.Rebase else "off."
print

print "[+] DataSections:"
print "[*] %-8s %-10s %-10s %-10s" % ("name", "vaddr", "offset", "size")
for section in pe.DataSections:
	print "   %-8s 0x%-08x 0x%-08x 0x%-08x" % (section["name"], section["vaddr"], section["offset"], section["size"])
print "[+] Total: %d datasection." % (len(pe.DataSections))
print

print "[+] ExecSections:"
print "[*] %-8s %-10s %-10s %-10s" % ("name", "vaddr", "offset", "size")
for section in pe.ExecSections:
	print "   %-8s 0x%-08x 0x%-08x 0x%-08x" % (section["name"], section["vaddr"], section["offset"], section["size"])
print "[+] Total: %d execsection." % (len(pe.ExecSections))
print
