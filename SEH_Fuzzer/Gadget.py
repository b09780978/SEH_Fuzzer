from PE import *
from util import *
import sys
from capstone import *
import re

MAX_DEPTH = 10
PATTERN		 = 0
PATTERN_SIZE = 1
CODE_SIZE	 = 2
OPCODE		 = 3

RetGadgetFormat = [
	[b"\xc3", 1, 1, "ret"],			 # ret(near)
	[b"\xcb", 1, 1, "ret"],			 # ret(far)
	#[b"\xc2{\x00-\xff}", 3, 1, "ret"],  # ret imm16(near)
	#[b"\xca{\x00-\xff}", 3, 1, "ret"],  # ret imm16(far)
	]
	
SysGadgetFormat = [
	[b"\x0f\x05", 2, 1, "syscall"],		 # syscall
	[b"\xcd\x80", 2, 1, "int 0x80"]		 # int 0x80
	]
	
'''
	filiter gadget whether contain newline
'''
def gadget_filter(gadget):
	return False if "\x0a" in p32(gadget) else True
	
class Gadget(object):
	def __init__(self, pe):
		self.__pe = pe
		self.__disassembler = Cs(pe.ArchMode, pe.BitsMode)
		self.__execSections = self.__pe.ExecSections
		self.__dataSections = self.__pe.DataSections
		
		self.__retGadgets = self.collect_gadgets(RetGadgetFormat)
		self.__sysGadgets = self.collect_gadgets(SysGadgetFormat)
		
	def collect_gadgets(self, GadgetFormat):
		Gadgets = []
		for section in self.__execSections:
			code = section["code"]
			for targetGadget in GadgetFormat:
				retPostions = [ pos.start() for pos in re.finditer(targetGadget[PATTERN], code) ]
				for position in retPostions:
					for deep in xrange(MAX_DEPTH+1):
						start = section["vaddr"] + position - deep * targetGadget[CODE_SIZE]
						if (start % targetGadget[CODE_SIZE] == 0) and gadget_filter(start):
							pattern = self.__disassembler.disasm( code[ position - deep * targetGadget[CODE_SIZE] : position + targetGadget[PATTERN_SIZE] ], 0 )
							gadget = ""
							
							for instruction in pattern:
								gadget += (instruction.mnemonic + " " + instruction.op_str + " ; ").replace("  ", " ")
							
							if len(gadget)>0 and targetGadget[OPCODE] in gadget.split(" ; ")[-2] :
								gadget = gadget[:-3]
						
								Gadgets += [
									{
										"vaddr" : start,
										"gadgets" : gadget,
										"bytes" : code[ position - deep * targetGadget[CODE_SIZE] : position + targetGadget[PATTERN_SIZE] ]
									}
								]
		return Gadgets
	
	@property
	def retGadgets(self):
		return self.__retGadgets
	
	@property
	def sysGadgets(self):
		return self.__sysGadgets
		