import pefile
from capstone import *

'''
	Windows PE file arch code.
	Ref: https://msdn.microsoft.com/zh-tw/library/windows/desktop/ms680547(v=vs.85).aspx#machine_types
'''
class ArchFlag:
	IMAGE_FILE_MACHINE_UNKNOWN	= 0x0
	IMAGE_FILE_MACHINE_AMD64 	= 0x8664
	IMAGE_FILE_MACHINE_I386  	= 0x14c
	IMAGE_FILE_MACHINE_IA64  	= 0x200
	
'''
	Get PE file characteristics.
	Can grad some characteristics of PE file.
	Ref: https://msdn.microsoft.com/zh-tw/library/windows/desktop/ms680547(v=vs.85).aspx#characteristics
'''
class FileHeaderCharacteristicsFlag:
	IMAGE_FILE_RELOCS_STRIPPED = 0x1
	IMAGE_FILE_32BIT_MACHINE   = 0x100
	IMAGE_FILE_SYSTEM		   = 0x1000
	IMAGE_FILE_DLL 			   = 0x2000
	
'''
	Get file bits.
'''
class MagicFlag:
	PE32 	 = 0x10b	# for 32bit
	PE32plus = 0x20b	# for 64bit
	
'''
	Get DLL characteristics.
	Ref: https://msdn.microsoft.com/zh-tw/library/windows/desktop/ms680547(v=vs.85).aspx#dll_characteristics
'''
class DllCharacteristicsFlag:
	IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x40
	IMAGE_DLLCHARACTERISTICS_NX_COMPAT    = 0x100
	IMAGE_DLLCHARACTERISTICS_NO_SEH      = 0x400
	
'''
	Section Flag Definition.
	Ref: https://msdn.microsoft.com/zh-tw/library/windows/desktop/ms680547(v=vs.85).aspx#section_flags
'''
class SectionFlag:
	IMAGE_SCN_MEM_EXECUTE = 0x20000000
	IMAGE_SCN_MEM_READ = 0x40000000
	IMAGE_SCN_MEM_WRITE = 0x80000000
	
'''
	PE parse error exception, will add a message about error.
'''
class PEError(Exception):
	def __init__(self, message="Parse PE file fail"):
		self.message = message
		
	def __str__(self):
		return repr(self.message)
	
class PE(object):
	def __init__(self, exe_path):
		self.__name = exe_path
		self.__parser = None
		self.__format = "PE"
		try:
			self.__parser = pefile.PE(exe_path, fast_load=True)
		except:
			self.__parser = None
			raise PEError("[-] Open %s fail." % (self.Name))
		
		self.Arch = self.__parser.FILE_HEADER.Machine
		self.__type = "dll" if self.__parser.FILE_HEADER.Characteristics & FileHeaderCharacteristicsFlag.IMAGE_FILE_DLL else "exe"
		
		if self.__type == "exe" and (self.__parser.FILE_HEADER.Characteristics & FileHeaderCharacteristicsFlag.IMAGE_FILE_RELOCS_STRIPPED):
			self.__rebase = False
		elif self.__type == "dll" and not (self.__parser.OPTIONAL_HEADER.DllCharacteristics & DllCharacteristicsFlag.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE):
			self.__rebase = False
		else:
			self.__rebase = True
		
		if self.__parser.OPTIONAL_HEADER.Magic & MagicFlag.PE32:
			self.__bits = 32
			self.__bitMode = CS_MODE_32
		elif self.__parser.OPTIONAL_HEADER.Magic & MagicFlag.PE32plus:
			self.__bits = 64
			self.__bitMode = CS_MODE_64
		
		self.__entryPoint = self.__parser.OPTIONAL_HEADER.ImageBase + self.__parser.OPTIONAL_HEADER.AddressOfEntryPoint
		
		self.__dataSections = None
		self.__execSections = None
		
		self.__getDataSections()
		self.__getExecSections()
		
		self.__parser.close()
		
	def __getDataSections(self):
		dataSections = []
		for section in self.__parser.sections:
			if section.Characteristics & SectionFlag.IMAGE_SCN_MEM_WRITE:
				dataSections.append({
					"name" : section.Name,
					"offset" : section.PointerToRawData,
					"size" : section.SizeOfRawData,
					"vaddr" : section.VirtualAddress + self.__parser.OPTIONAL_HEADER.ImageBase,
					"code" : str(section.get_data())
				})
		self.__dataSections = dataSections
		
	def __getExecSections(self):
		execSections = []
		for section in self.__parser.sections:
			if section.Characteristics & SectionFlag.IMAGE_SCN_MEM_EXECUTE:
				execSections.append({
					"name" : section.Name,
					"offset" : section.PointerToRawData,
					"size" : section.SizeOfRawData,
					"vaddr" : section.VirtualAddress + self.__parser.OPTIONAL_HEADER.ImageBase,
					"code" : bytes(section.get_data())
				})
		self.__execSections = execSections
		
	@property
	def Arch(self):
		return self.__Arch
	
	@Arch.setter
	def Arch(self, flag):
		self.__Arch = { 
				 ArchFlag.IMAGE_FILE_MACHINE_UNKNOWN : "All",
				 ArchFlag.IMAGE_FILE_MACHINE_AMD64 	 : "amd64",
				 ArchFlag.IMAGE_FILE_MACHINE_I386  	 : "intel",
				 ArchFlag.IMAGE_FILE_MACHINE_IA64  	 : "ia64"
				}.get(flag, "unknow")
				
		if self.__Arch == "unknow":
			raise PEError("[-] %s is not arch." % (self.Name))
				 
		self.__ArchMode = {
					ArchFlag.IMAGE_FILE_MACHINE_UNKNOWN : CS_ARCH_ALL,
					ArchFlag.IMAGE_FILE_MACHINE_AMD64 	 : CS_ARCH_X86,
					ArchFlag.IMAGE_FILE_MACHINE_I386  	 :  CS_ARCH_X86,
					ArchFlag.IMAGE_FILE_MACHINE_IA64  	 :  CS_ARCH_X86
				}.get(flag, None)
				
		if self.__ArchMode is None:
			raise PEError("[-] %s is not support." % (self.Name))
				
	@property
	def ArchMode(self):
		return self.__ArchMode
	
	@property
	def Bits(self):
		return self.__bits
		
	@property
	def BitsMode(self):
		return self.__bitMode
	
	@property
	def DataSections(self):
		return self.__dataSections
		
	@property
	def ExecSections(self):
		return self.__execSections
		
	@property
	def EntryPoint(self):
		return self.__entryPoint
	
	@property
	def Format(self):
		return self.__format
	
	@property 
	def Rebase(self):
		return self.__rebase
		
	@property
	def Name(self):
		return self.__name
	
	@property
	def Type(self):
		return self.__type
