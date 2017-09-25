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
	[b"\xc2[\x00-\xff]{2}", 3, 1, "ret"],  # ret imm16(near)
	[b"\xca[\x00-\xff]{2}", 3, 1, "ret"],  # ret imm16(far)
	]
	
SysGadgetFormat = [
	[b"\x0f\x05", 2, 1, "syscall"],		 # syscall
	[b"\xcd\x80", 2, 1, "int 0x80"]		 # int 0x80
	]

JmpGadgetFormat = [
	[b"\xff[\x20\x21\x22\x23\x26\x27]{1}", 2, 1, "jmp e"],     # jmp  [register]
	[b"\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}", 2, 1, "jmp e"], # jmp  [register]
	[b"\xff[\x10\x11\x12\x13\x16\x17]{1}", 2, 1, "jmp e"],     # jmp  [register]
	[b"\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}", 2, 1, "call e"],  # call [register]
	]
	
'''
	filiter gadget whether contain newline or nullbyte
'''
def gadget_filter(gadget):
	return False if ("\x0a" in p32(gadget)) or ( "\x00" in p32(gadget)) else True
	
class Gadget(dict):
	def __init__(self, pe):
		self.__pe = pe
		self.__disassembler = Cs(pe.ArchMode, pe.BitsMode)
		self.__execSections = self.__pe.ExecSections
		self.__dataSections = self.__pe.DataSections
		
		self.__retGadgets = self.collect_gadgets(RetGadgetFormat)
		self.__sysGadgets = self.collect_gadgets(SysGadgetFormat)
		self.__jmpGadgets = self.findJmp(JmpGadgetFormat)

	def findJmp(self, GadgetFormat):
		Gadgets = []
		for section in self.__execSections:
			code = section["code"]
			for targetGadget in GadgetFormat:
				retPostions = [ pos.start() for pos in re.finditer(targetGadget[PATTERN], code) ]
				for position in retPostions:
					start = section["vaddr"] + position
					pattern = self.__disassembler.disasm( code[ position:position+targetGadget[PATTERN_SIZE] ], 0 )
					gadget = ""

					for instruction in pattern:
						gadget += (instruction.mnemonic + " " + instruction.op_str + " ; ").replace("  ", " ")

					if len(gadget)>0 and gadget.startswith(targetGadget[OPCODE]) and gadget_filter(start):
						gadget = gadget[:-3]
						
						Gadgets += [
							{
								"vaddr" : start,
								"gadgets" : gadget,
								"bytes" : code[ position : position + targetGadget[PATTERN_SIZE]]
							}
						]

		return Gadgets

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

							if len(gadget)>0 and gadget.split(" ; ")[-2].find(targetGadget[OPCODE])!=-1 and gadget.count("ret")==1 and gadget.find("ret 0x")==-1 and gadget.find("ret -")==-1 and gadget.find("retf 0x")==-1 and gadget.find("retf -")==-1 and gadget.find("ret 1") == -1 and gadget.find("retf 1") == -1 and gadget.find("ret 2") == -1 and gadget.find("retf 2") == -1 and gadget.find("ret 3") == -1 and gadget.find("retf 3") == -1 and gadget.find("ret 4") == -1 and gadget.find("retf 4") == -1:
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
	def jmpGadgets(self):
		return self.__jmpGadgets

	@property
	def retGadgets(self):
		return self.__retGadgets
	
	@property
	def sysGadgets(self):
		return self.__sysGadgets
		
NUM_FORMAT = "(0x[\da-f]+)|(\d+)"

# Check gadget's instruction.
def check_gadget_pass(gadgets, allow, not_allow):
	patterns = gadgets.split(" ; ")
	statu = True
	counter = 0

	while counter<len(gadgets) and statu:
		check_ok = False
		for pattern in patterns:
			for allow_pattern in allow:
				if pattern.find(allow_pattern)!=-1:
					check_ok = True
					break

			if check_ok:
				for not_allow_pattern in not_allow:
					if pattern.startswith(not_allow_pattern):
						statu = False
						break
			else:
				statu = False
		counter += 1
	return statu

# Merge gadget by type
def merge_gadgets(gadget_type, new_gadgets, collection):
	if collection.has_key(gadget_type):
		collection[gadget_type].update(new_gadgets)
	else:
		collection[gadget_type] = new_gadgets

# Classify all gadget type.
'''
	+------+--------+-----+-----+-----+-----+-----+-------+-----+--------+--------+-----+-----+--------+--------+
	| type | pushad | xor | inc | dec | pop | neg | clear | add | addnum | jmpesp | nop | SEH | pickup | movreg |
	+------+--------+-----+-----+-----+-----+-----+-------+-----+--------+--------+-----+-----+--------+--------+
'''

def classify_gadget(all_gadgets, jmp_gadgets, collection):
	REGISTER = [ "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"]

	'''
		Add pushad gadget.
		+----------------+
		| pushad(puahal) |
		+----------------+
	'''
	# Instructions filter for pushad gadget.
	PUSHAD_ALLOW_INS = [ "pushad", "pushal", "inc ", "dec ", "add ", "sub ", "or ", "and ", "xor ", "adc ", "ret", "nop", "pop ", "lea ", "push eax", "push edi", "fpatan", "mov e", "test ", "cmp " ]
	PUSHAD_NOT_ALLOW_INS = [ "popad", "popal", "push esp", "pop esp", "inc esp", "dec esp", "add esp", "sub esp", "xor esp", "lea esp", "ss: ", "ds: " ]

	for register1 in REGISTER:
		# Change data in stack head or bottom.
		PUSHAD_ALLOW_INS.append("mov %s, dword ptr ds:[esp" % register1)
		PUSHAD_ALLOW_INS.append("mov %s, dword ptr ss:[esp" % register1)
		PUSHAD_ALLOW_INS.append("mov %s, dword ptr [esp" % register1)
		PUSHAD_ALLOW_INS.append("mov %s, dword ptr ds:[ebp" % register1)
		PUSHAD_ALLOW_INS.append("mov %s, dword ptr ss:[ebp" % register1)
		PUSHAD_ALLOW_INS.append("mov %s, dword ptr [ebp" % register1)
		# Put virtualprotect ptr to esi
		PUSHAD_ALLOW_INS.append("mov %s, dword ptr ds:[esi" % register1)
		PUSHAD_ALLOW_INS.append("mov %s, dword ptr ss:[esi" % register1)
		PUSHAD_ALLOW_INS.append("mov %s, dword ptr [esi" % register1)
		
		for register2 in REGISTER:
			PUSHAD_ALLOW_INS.append("mov %s, %s" % (register1, register2))
			PUSHAD_ALLOW_INS.append("lea %s, %s" % (register1, register2))
			PUSHAD_ALLOW_INS.append("xchg %s, %s" % (register1, register2))

	for g in all_gadgets:
		instructions = g["gadgets"]
		if instructions.startswith("pushad") or instructions.startswith("pushal"):
			if instructions.count("pop ")<2 and check_gadget_pass(instructions, PUSHAD_ALLOW_INS, PUSHAD_NOT_ALLOW_INS):
				new_gadget = { g["vaddr"] : g["gadgets"] }
				merge_gadgets("pushad", new_gadget, collection)

	'''
		Add xor gadgets.
		+-----+
		| xor |
		+-----+
	'''
	XOR_ALLOW_INS = ["nop", "ret", "pop ", "inc ", "dec ", "and ", "or ", "xor ", "push ", "xchg ", "adc ", "fpatan", "test ", "cmp "]
	
	for register1 in REGISTER:
		for register2 in REGISTER:
			if register1!=register2:
				XOR_NOT_ALLOW_INS = [ "pop " + register2, "mov " + register2, "xor " + register2, "and register2",
					"jmp ", "pushad", "pushal", "popad", "popal", "dec esp", "ds:", "ss:", "inc esp" ]
				for g in all_gadgets:
					instructions = g["gadgets"]
					if instructions.startswith("xor") and check_gadget_pass(instructions, XOR_ALLOW_INS, XOR_NOT_ALLOW_INS):
						new_gadget = {g["vaddr"] : g["gadgets"]}
						merge_gadgets("xor", new_gadget, collection)

	'''
		Add inc gadgets.
		+-----+
		| inc |
		+-----+
	'''
	for register1 in REGISTER:
		INC_ALLOW_INS = ["nop", "ret", "pop ", "inc " + register1, "dec ", "and ", "or ", "xor ", "push ", "xchg ", "adc ", "fpatan", "test ", "cmp "]
		INC_NOT_ALLOW_INS = [ "pop " + register1, "mov " + register1 + ",", "xchg " + register1 + ",", "xor " + register1, "lea " + register1 + ",", "dec " + register1,
			"ds:", "ss:", "dec esp", "inc esp" ]
		for g in all_gadgets:
			instructions = g["gadgets"]
			if instructions.startswith("inc") and check_gadget_pass(instructions, INC_ALLOW_INS, INC_NOT_ALLOW_INS):
				new_gadget = { g["vaddr"] : g["gadgets"] }
				merge_gadgets("inc", new_gadget, collection)

	'''
		Add dec gadgets
		+-----+
		| dec |
		+-----+
	'''
	for register1 in REGISTER:
		DEC_ALLOW_INS = ["nop", "ret", "pop ", "dec " + register1, "dec ", "and ", "or ", "xor ", "push ", "xchg ", "adc ", "fpatan", "test ", "cmp "]
		DEC_NOT_ALLOW_INS = [ "pop " + register1, "mov " + register1 + ",", "xchg " + register1 + ",", "xor " + register1, "lea " + register1 + ",", "inc " + register1,
			"ds:", "ss:", "dec esp", "inc esp" ]
		for g in all_gadgets:
			instructions = g["gadgets"]
			if instructions.startswith("dec") and check_gadget_pass(instructions, DEC_ALLOW_INS, DEC_NOT_ALLOW_INS):
				new_gadget = { g["vaddr"] : g["gadgets"] }
				merge_gadgets("dec", new_gadget, collection)

	'''
		Add pop gadgets
		+-----+
		| pop |
		+-----+
	'''
	for register1 in REGISTER:
		POP_ALLOW_INS = "pop %s ; ret" % register1
		for g in all_gadgets:
			instructions = g["gadgets"]
			if instructions.startswith(POP_ALLOW_INS):
				new_gadget = { g["vaddr"] : g["gadgets"] }
				merge_gadgets("pop", new_gadget, collection)

	'''
		Add neg gadgets.
		+-----+
		| neg |
		+-----+
	'''
	for register1 in REGISTER:
		NEG_ALLOW_INS = "neg %s ; ret" % register1
		for g in all_gadgets:
			instructions = g["gadgets"]
			if instructions.startswith(NEG_ALLOW_INS):
				new_gadget = { g["vaddr"] : g["gadgets"] }
				merge_gadgets("neg", new_gadget, collection)

	'''
		Add clear register.
	'''
	for register1 in REGISTER:
		CLEAR_ALLOW_INS = [ "xor " + register1 + ", " + register1 + " ; ret", "mov " + register1 + ", 0xffffffff ; inc " + register1 + " ; ret",
						"sub " + register1 + ", " + register1 + " ; ret", "push 0 ; pop " + register1 + " ; ret", "imul " + register1 + ", " + register1 + ", 0 ; ret" ]
		for g in all_gadgets:
			instructions = g["gadgets"]
			for pattern in CLEAR_ALLOW_INS:
				if instructions.startswith(pattern):
					new_gadget = { g["vaddr"] : g["gadgets"] }
					merge_gadgets("clear", new_gadget, collection)

	'''
		Add add register1, register2 gadget.
		+----------------+
		| add reg1, reg2 |
		+----------------+
	'''
	for register1 in REGISTER:
		for register2 in REGISTER:
			if register1!=register2:
				ADD_ALLOW_INS = [ "nop", "ret", "pop ", "inc ", "dec ", "and", "or ", "xor ","add ", "adc ", "sub ", "fpatan", "test ", "cmp ", "mov eax" ]
				ADD_NOT_ALLOW_INS = [ "pop " + register1, "mov " + register1 + ",", "xchg " + register1 + ",", "xor " + register1, "lea " + register1 + ",",
								"ds: ", "ss: ", "dec esp", "inc esp", "mov eax, dword ptr [eax" ]
				head = [ "add " + register1 + ", " + register2, "adc " + register1 + ", " + register2  ]
				for g in all_gadgets:
					instructions = g["gadgets"]
					for pattern in head:
						if instructions.startswith(pattern) and check_gadget_pass(instructions, ADD_ALLOW_INS, ADD_NOT_ALLOW_INS):
							new_gadget = { g["vaddr"] : g["gadgets"] }
							merge_gadgets("add", new_gadget, collection)

	'''
		Add add num gadget.
		+--------------+
		| add reg, num |
		+--------------+
	'''
	for register1 in REGISTER + ["esp"]:
		ADDNUM_ALLOW_INS = [ "nop" , "ret" , "pop ", "inc ", "dec ", "and", "or ", "push ", "adc ", "sub ", "fpatan", "test ", "cmp " ]
		ADDNUM_NOT_ALLOW_INS = ["pop " + register1, "mov " + register1 + ",", "xchg " + register1 + ",", "xor " + register1, "lea " + register1 + ",",
							"ds:", "ss:", "dec esp" ]
		head = [ "add " + register1 + ",", "adc " + register1 + ",", "sub " + register1 + ","]
		for g in all_gadgets:
			instructions = g["gadgets"]
			if instructions.startswith(head[0]) or instructions.startswith(head[1]) or instructions.startswith(head[2]):
				if re.search(NUM_FORMAT, instructions.split(",")[1].split(" ; ")[0]) is None:
					break
				else:
					instructions = (" ; ").join(instructions.split(" ; ")[1:])
				if check_gadget_pass(instructions, ADDNUM_ALLOW_INS, ADDNUM_NOT_ALLOW_INS):
					new_gadget = { g["vaddr"] : g["gadgets"] }
					merge_gadgets("addnum", new_gadget, collection)

	'''
		Add jmp esp gadget.
		+---------------+
		| jmp(call) reg |
		+---------------+
	'''
	for register1 in REGISTER + ["esp"]:
		JMP_ALLOW_INS = [ "jmp " + register1, "call " + register1, "push esp ; ret" ]
		for g in all_gadgets:
			instructions = g["gadgets"]
			for pattern in JMP_ALLOW_INS:
				if instructions.startswith(pattern):
					new_gadget = { g["vaddr"] : g["gadgets"] }
					merge_gadgets("jmpesp", new_gadget, collection)

	for g in jmp_gadgets:
		new_gadget = { g["vaddr"] : g["gadgets"] }
		merge_gadgets("jmpesp", new_gadget, collection)

	'''
		Add nop gadget.
		+-----+
		| nop |
		+-----+
	'''
	NOP_ALLOW_INS = [ "nop", "ret", "retf", "retn"]
	for g in all_gadgets:
		instruction = g["gadgets"].split(" ; ")
		check_ok = True
		for pattern in instruction:
			if pattern not in NOP_ALLOW_INS:
				check_ok = False
				break
		if check_ok:
			new_gadget = { g["vaddr"] : g["gadgets"] }
			merge_gadgets("nop", new_gadget, collection)

	'''
		Add SEH pop pop ret gadget.
		+-----+
		| SEH |
		+-----+
	'''

	SEH_ALLOW_INS = ["add esp, 8 ; ret", "add esp,4 ; add esp, 4 ; ret"]
	for register1 in REGISTER:
		SEH_ALLOW_INS.append("add esp,4 ; pop " + register1 + " ; ret")
		SEH_ALLOW_INS.append("pop " + register1 + "add esp,4 ; ret")
		for register2 in REGISTER:
			SEH_ALLOW_INS.append("pop " + register1 + " ; pop " + register2 + " ; ret")

	for g in all_gadgets:
		instruction = g["gadgets"]
		for pattern in SEH_ALLOW_INS:
			if instruction.startswith(pattern):
				new_gadget = { g["vaddr"] : g["gadgets"]}
				merge_gadgets("seh", new_gadget, collection)

	'''
		Add pickup gadget.
		+----------------------------+
		| mov reg1, dword ptr [reg2] |
		+----------------------------+
	'''

	PICKUP_ALLOW_INS = [ "nop", "ret", "inc ", "dec ", "and ", "or ", "xor ", "mov ", "lea ", "add ", "sub ", "adc ",
				"pop ", "fpatan", "test ", "cmp " ]
	PICKUP_NOT_ALLOW_INS = [ "mov esp", "xor esp", "lea esp", "mov dword ptr", "dec esp", "inc esp", "call 0x", "jmp", "jne", "leave" ]
	for register1 in REGISTER:
		for register2 in REGISTER:
			PICKUP_REGISTER1 = PICKUP_ALLOW_INS + [ "mov " + register1 + ", dword ptr [" + register2 + "]" ]
			PICKUP_REGISTER1.append("mov " + register1 + ", dword ptr ss: [" + register2 + "]")
			PICKUP_REGISTER1.append("mov " + register1 + ", dword ptr ds: [" + register2 + "]")
			header = []
			header.append("mov " + register1 + ", dword ptr [" + register2 + "]")
			header.append("mov " + register1 + ", dword ptr ss: [" + register2 + "]")
			header.append("mov " + register1 + ", dword ptr ds: [" + register2 + "]")
			PICKUP_NOT_REGISTER1 = PICKUP_NOT_ALLOW_INS + [ "pop " + register1, "lea " + register1 + ", e"]
			pickupType = "pickup" + register1 + register2
			for g in all_gadgets:
				instructions = g["gadgets"]
				for head in header:
					if instructions.startswith(head) and instructions.count("dword ptr")==1:
						# print "check %s." % instructions
						if check_gadget_pass(instructions, PICKUP_REGISTER1, PICKUP_NOT_REGISTER1):
							new_gadget = { g["vaddr"] : g["gadgets"] }
							merge_gadgets(pickupType, new_gadget, collection)

	'''
		Add movreg gadget.
		+----------------+
		| mov reg1, reg2 |
		+----------------+
	'''
	MOVREG_ALLOW_INS = ["nop", "ret", "pop ", "inc ", "dec ", "add ", "sub ", "and ", "or ", "xor ", "xchg", "fpatan", "cmp ", "test " ]
	MOVREG_NOT_ALLOW_INS = [ "ds:", "ss:", "pushad", "pushal", "popad", "popal", "dec esp", "inc esp", "call 0x", "jmp", "leave", "jne"]
			# "ret 0x", "ret -", "ret 1", "ret 4", "ret 8", "retf -0x", "retf 0x", "retf 1" "retf 4", "retf 8" ]
	for register1 in REGISTER:
		for register2 in REGISTER:
			MOV_TYPE = "mov"+register1+register2
			MOVREG_ALLOW = MOVREG_ALLOW_INS + [ "mov " + register1 + ", " + register2 ]
			MOVREG_ALLOW.append("lea " + register1 + ", " + register2)
			MOVREG_ALLOW.append("xchg " + register1 + ", " + register2)
			MOVREG_ALLOW.append("xchg " + register2 + ", " + register1)
			MOVREG_NOT_ALLOW = MOVREG_NOT_ALLOW_INS + [ "pop " + register2 ]
			MOVREG_NOT_ALLOW += [ "lea " + register2, "mov " + register2, "xor " + register2, "and " + register2]
			header = []
			header.append("lea " + register1 + ", " + register2)
			header.append("xchg " + register1 + ", " + register2)
			header.append("xchg " + register2 + ", " + register1)
			for g in all_gadgets:
				instructions = g["gadgets"]
				for head in header:
					if instructions.startswith(head) and check_gadget_pass(instructions, MOVREG_ALLOW, MOVREG_NOT_ALLOW):
						new_gadget = { g["vaddr"] : g["gadgets"] }
						merge_gadgets(MOV_TYPE, new_gadget, collection)