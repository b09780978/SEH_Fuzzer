from PE import *
import unittest

'''
	TestCase information
'''

NORMAL_EXE = "..\\Vuln\\fsws.exe"
NORMAL_DLL = "..\\Vuln\\ImageLoad.dll"
ERROR_EXE = "abc.exe"
ERROR_DLL = "abc.dll"

TESTCASES = {
	NORMAL_EXE : {
		"ARCH" : "intel",
		"TYPE" : "exe",
		"FORMAT" : "PE",
		"BITS" : 32,
		"ENTRYPOINT" : 0x004fc060,
		"REBASE" : False
	},
	NORMAL_DLL : {
		"ARCH" : "intel",
		"TYPE" : "dll",
		"FORMAT" : "PE",
		"BITS" : 32,
		"ENTRYPOINT" : 0x1001ab40,
		"REBASE" : False
	},
	ERROR_EXE : {
		
	},
	ERROR_DLL : {
	
	}
}

class PETestCase(unittest.TestCase):
	'''
		Basic setUp(),tearDown() and log() functions
	'''
	def setUp(self):
		self.pe = None

	def tearDown(self):
		self.pe = None
		
	def log(self, testcase):
		print "[+] Passing TestCase %s." % (testcase)
		
	'''
		test normal testcase
	'''

	def test_NORMAL_EXE(self):
		self.pe = PE(NORMAL_EXE)
		self.assertEqual(self.pe.Arch, TESTCASES[NORMAL_EXE]["ARCH"])
		self.assertEqual(self.pe.Type, TESTCASES[NORMAL_EXE]["TYPE"])
		self.assertEqual(self.pe.Format, TESTCASES[NORMAL_EXE]["FORMAT"])
		self.assertEqual(self.pe.Bits, TESTCASES[NORMAL_EXE]["BITS"])
		self.assertEqual(self.pe.EntryPoint, TESTCASES[NORMAL_EXE]["ENTRYPOINT"])
		self.assertEqual(self.pe.Rebase, TESTCASES[NORMAL_EXE]["REBASE"])
		self.log("MNORMAL_EXE: " + NORMAL_EXE)
		
	def test_NORMAL_DLL(self):
		self.pe = PE(NORMAL_DLL)
		self.assertEqual(self.pe.Arch, TESTCASES[NORMAL_DLL]["ARCH"])
		self.assertEqual(self.pe.Type, TESTCASES[NORMAL_DLL]["TYPE"])
		self.assertEqual(self.pe.Format, TESTCASES[NORMAL_DLL]["FORMAT"])
		self.assertEqual(self.pe.Bits, TESTCASES[NORMAL_DLL]["BITS"])
		self.assertEqual(self.pe.EntryPoint, TESTCASES[NORMAL_DLL]["ENTRYPOINT"])
		self.assertEqual(self.pe.Rebase, TESTCASES[NORMAL_DLL]["REBASE"])
		self.log("NNORMAL_DLL: " + NORMAL_DLL)
		
	'''
		test error testcase
	'''
	def test_ERROR_EXE(self):
		try:
			self.pe = PE(ERROR_EXE)
		except Exception as e:
			self.assertTrue( isinstance(e, PEError))
		self.log("ERROR_EXE: " + ERROR_EXE)
			
	def test_ERROR_DLL(self):
		try:
			self.pe = PE(ERROR_DLL)
		except Exception as e:
			self.assertTrue( isinstance(e, PEError))
		self.log("EERROR_DLL: " + ERROR_DLL)

if __name__ == "__main__":
	unittest.main()