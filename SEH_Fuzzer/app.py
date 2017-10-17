from kivy.app import App
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button

import subprocess
import cPickle
import os

class Column(GridLayout):
	def __init__(self, cols, **kwargs):
		super(Row, self).__init__(**kwargs)
		self.cols = cols
		

class Screen(GridLayout):
	def __init__(self, **kwargs):
		super(Screen, self).__init__(**kwargs)
		self.cols = 2
		self.add_widget(Label(text="Target"))
		self.target = TextInput(multiline=False)
		self.add_widget(self.target)
		self.add_widget(Label(text="target info"))
		self.setting = TextInput()
		self.add_widget(self.setting)
		fuzz_btn = Button(text="Fuzz")
		self.add_widget(fuzz_btn)
		self.result = Label(text="None")
		self.add_widget(self.result)
		fuzz_btn.bind(on_press=self.show_result)

	def show_result(self, obj):
		try:
			proc = subprocess.check_call("python Seh_bug_Fuzzer.py", shell=True)
			with open("crash_info.pkl", "rb") as f:
				max_offset = cPickle.load(f)
				seh_offset = cPickle.load(f)

			RESULT = "[+] When send %d words will crash.\n" % (max_offset)
			RESULT += "[+] Overwrite SEH structure need %d words.\n" % (seh_offset)
			RESULT += "[+] Dump crash stack in crash.txt."
			self.result.text = RESULT
			
			subprocess.check_call("notepad crash.txt", shell=True)
				
		except Exception as e:
			print str(e)
			self.result.text += "[-] Fail."
			print '[-] Fail'

class MyApp(App):
	def build(self):
		return Screen()

if __name__ == "__main__":
	MyApp().run()