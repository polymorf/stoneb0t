#!/usr/bin/python2
from capstone import *
from keystone import *
from ast import literal_eval
import sys


class botCli():
	def __init__(self):
		self.supported_keystone_archs = self.__get_supported_keystone_archs()
		self.supported_capstone_archs = self.__get_supported_capstone_archs()

	def send_msg(self, dest, msg):
		sys.stdout.write(msg + "\n")

	def __get_supported_capstone_archs(self):
		capstone_archs={}
		if cs_support(CS_ARCH_X86):
			capstone_archs["x16"] = {
				"desc":"16-bit mode (X86)",
				"CS_ARCH": CS_ARCH_X86,
				"CS_MODE": CS_MODE_16
			}
			capstone_archs["x32"] = {
				"desc":"32-bit mode (X86)",
				"CS_ARCH": CS_ARCH_X86,
				"CS_MODE": CS_MODE_32
			}
			capstone_archs["x64"] = {
				"desc":"64-bit mode (X86)",
				"CS_ARCH": CS_ARCH_X86,
				"CS_MODE": CS_MODE_64
			}
		if cs_support(CS_ARCH_ARM):
			capstone_archs["arm"] = {
				"desc":"arm",
				"CS_ARCH": CS_ARCH_ARM,
				"CS_MODE": CS_MODE_ARM
			}
			capstone_archs["armb"] = {
				"desc":"arm + big endian",
				"CS_ARCH": CS_ARCH_ARM,
				"CS_MODE": CS_MODE_ARM + CS_MODE_BIG_ENDIAN
			}
			capstone_archs["arml"] = {
				"desc":"arm + little endian",
				"CS_ARCH": CS_ARCH_ARM,
				"CS_MODE": CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN
			}
			capstone_archs["thumb"] = {
				"desc":"thumb mode",
				"CS_ARCH": CS_ARCH_ARM,
				"CS_MODE": CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN
			}
			capstone_archs["thumbbe"] = {
				"desc":"thumb + big endian",
				"CS_ARCH": CS_ARCH_ARM,
				"CS_MODE": CS_MODE_THUMB + CS_MODE_BIG_ENDIAN
			}
			capstone_archs["thumble"] = {
				"desc":"thumb + billtle endian",
				"CS_ARCH": CS_ARCH_ARM,
				"CS_MODE": CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN
			}
		if cs_support(CS_ARCH_ARM64):
			capstone_archs["arm64"] = {
				"desc":"aarch64 mode",
				"CS_ARCH": CS_ARCH_ARM64,
				"CS_MODE": CS_MODE_LITTLE_ENDIAN
			}
		if cs_support(CS_ARCH_MIPS):
			capstone_archs["mips"] = {
				"desc":"mips32 + little endian",
				"CS_ARCH": CS_ARCH_MIPS,
				"CS_MODE": CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN
			}
			capstone_archs["mipsbe"] = {
				"desc":"mips32 + big endian",
				"CS_ARCH": CS_ARCH_MIPS,
				"CS_MODE": CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN
			}
			capstone_archs["mips64"] = {
				"desc":"mips64 + little endian",
				"CS_ARCH": CS_ARCH_MIPS,
				"CS_MODE": CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN
			}
			capstone_archs["mips64be"] = {
				"desc":"mips64 + big endian",
				"CS_ARCH": CS_ARCH_MIPS,
				"CS_MODE": CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN
			}
		if cs_support(CS_ARCH_PPC):
			capstone_archs["ppc64"] = {
				"desc":"ppc64 + little endian",
				"CS_ARCH": CS_ARCH_PPC,
				"CS_MODE": CS_MODE_64+CS_MODE_LITTLE_ENDIAN
			}
			capstone_archs["ppc64be"] = {
				"desc":"ppc64 + big endian",
				"CS_ARCH": CS_ARCH_PPC,
				"CS_MODE": CS_MODE_64+CS_MODE_BIG_ENDIAN
			}
		if cs_support(CS_ARCH_SPARC):
			capstone_archs["sparc"] = {
				"desc":"sparc",
				"CS_ARCH": CS_ARCH_SPARC,
				"CS_MODE": CS_MODE_BIG_ENDIAN
			}
		if cs_support(CS_ARCH_SYSZ):
			capstone_archs["systemz"] = {
				"desc":"systemz (s390x)",
				"CS_ARCH": CS_ARCH_SYSZ,
				"CS_MODE": CS_MODE_BIG_ENDIAN
			}
		if cs_support(CS_ARCH_XCORE):
			capstone_archs["xcore"] = {
				"desc":"xcore",
				"CS_ARCH": CS_ARCH_XCORE,
				"CS_MODE": CS_MODE_BIG_ENDIAN
			}
		return capstone_archs

	def __get_supported_keystone_archs(self):
		keystone_archs={}
		if ks_arch_supported(KS_ARCH_X86):
			keystone_archs["x16"]	= {
				"desc":"X86 16bit, Intel syntax",
				"KS_ARCH":KS_ARCH_X86,
				"KS_MODE":KS_MODE_16
			}
			keystone_archs["x32"]	= {
				"desc":"X86 32bit, Intel syntax",
				"KS_ARCH":KS_ARCH_X86,
				"KS_MODE":KS_MODE_32
			}
			keystone_archs["x64"]	= {
				"desc":"X86 64bit, Intel syntax",
				"KS_ARCH":KS_ARCH_X86,
				"KS_MODE":KS_MODE_64
			}
		if ks_arch_supported(KS_ARCH_ARM):
			keystone_archs["arm"] = {
				"desc":"ARM - little endian",
				"KS_ARCH": KS_ARCH_ARM,
				"KS_MODE": KS_MODE_ARM + KS_MODE_LITTLE_ENDIAN
			}
			keystone_archs["armbe"] = {
				"desc":"ARM - big endian",
				"KS_ARCH": KS_ARCH_ARM,
				"KS_MODE": KS_MODE_ARM + KS_MODE_BIG_ENDIAN
			}
			keystone_archs["thumb"] = {
				"desc":"Thumb - little endian",
				"KS_ARCH": KS_ARCH_ARM,
				"KS_MODE": KS_MODE_THUMB + KS_MODE_LITTLE_ENDIAN
			}
			keystone_archs["thumbbe"] = {
				"desc":"Thumb - big endian",
				"KS_ARCH": KS_ARCH_ARM,
				"KS_MODE": KS_MODE_THUMB + KS_MODE_BIG_ENDIAN
			}
		if ks_arch_supported(KS_ARCH_ARM64):
			keystone_archs["arm64"] = {
				"desc":"AArch64",
				"KS_ARCH": KS_ARCH_ARM64,
				"KS_MODE": KS_MODE_LITTLE_ENDIAN
			}
		if ks_arch_supported(KS_ARCH_HEXAGON):
			keystone_archs["hexagon"] = {
				"desc":"Hexagon",
				"KS_ARCH": KS_ARCH_HEXAGON,
				"KS_MODE": KS_MODE_BIG_ENDIAN
			}
		if ks_arch_supported(KS_ARCH_MIPS):
			keystone_archs["mips"] = {
				"desc":"Mips - little endian",
				"KS_ARCH": KS_ARCH_MIPS,
				"KS_MODE": KS_MODE_MIPS32+KS_MODE_LITTLE_ENDIAN
			}
			keystone_archs["mipsbe"] = {
				"desc":"Mips - big endian",
				"KS_ARCH": KS_ARCH_MIPS,
				"KS_MODE": KS_MODE_MIPS32+KS_MODE_BIG_ENDIAN
			}
			keystone_archs["mips64"] = {
				"desc":"Mips64 - little endian",
				"KS_ARCH": KS_ARCH_MIPS,
				"KS_MODE": KS_MODE_MIPS64+KS_MODE_LITTLE_ENDIAN
			}
			keystone_archs["mips64be"] = {
				"desc":"Mips64 - big endian",
				"KS_ARCH": KS_ARCH_MIPS,
				"KS_MODE": KS_MODE_MIPS64+KS_MODE_BIG_ENDIAN
			}
		if ks_arch_supported(KS_ARCH_PPC):
			keystone_archs["ppc32be"] = {
				"desc":"PowerPC32 - big endian",
				"KS_ARCH": KS_ARCH_PPC,
				"KS_MODE": KS_MODE_PPC32+KS_MODE_BIG_ENDIAN
			}
			keystone_archs["ppc64"] = {
				"desc":"PowerPC64 - little endian",
				"KS_ARCH": KS_ARCH_PPC,
				"KS_MODE": KS_MODE_PPC64+KS_MODE_LITTLE_ENDIAN
			}
			keystone_archs["ppc64be"] = {
				"desc":"PowerPC64 - big endian",
				"KS_ARCH": KS_ARCH_PPC,
				"KS_MODE": KS_MODE_PPC64+KS_MODE_BIG_ENDIAN
			}
		if ks_arch_supported(KS_ARCH_SPARC):
			keystone_archs["sparc"] = {
				"desc":"Sparc - little endian",
				"KS_ARCH": KS_ARCH_SPARC,
				"KS_MODE":  KS_MODE_SPARC32+KS_MODE_LITTLE_ENDIAN
			}
			keystone_archs["sparcbe"] = {
				"desc":"Sparc - big endian",
				"KS_ARCH": KS_ARCH_SPARC,
				"KS_MODE": KS_MODE_SPARC32+KS_MODE_BIG_ENDIAN
			}
			keystone_archs["sparc64"] = {
				"desc":"Sparc64 - little endian",
				"KS_ARCH": KS_ARCH_SPARC,
				"KS_MODE": KS_MODE_SPARC64+KS_MODE_LITTLE_ENDIAN
			}
			keystone_archs["sparc64be"] = {
				"desc":"Sparc64 - big endian",
				"KS_ARCH": KS_ARCH_SPARC,
				"KS_MODE": KS_MODE_SPARC64+KS_MODE_BIG_ENDIAN
			}
		return keystone_archs

	def __send_assembler_archlist(self,dest):
		msg = "Available assembler archs :"
		self.send_msg(dest,msg)
		for arch in sorted(self.supported_keystone_archs.keys()):
			msg="    %s%s%s" % (arch," "*(12-len(arch)),self.supported_keystone_archs[arch]["desc"])
			self.send_msg(dest,msg)

	def __send_disassembler_archlist(self,dest):
		msg = "Available disassembler archs :"
		self.send_msg(dest,msg)
		for arch in sorted(self.supported_capstone_archs.keys()):
			msg="    %s%s%s" % (arch," "*(12-len(arch)),self.supported_capstone_archs[arch]["desc"])
			self.send_msg(dest,msg)

	def __send_help(self,dest):
		keystone_version = ".".join(map(str,ks_version()))
		capstone_version = ".".join(map(str,cs_version()))
		msg = "%s running keystone %s, capstone %s\n" % (self._nick,keystone_version,capstone_version)
		msg += "help :\n"
		msg += '    !list-assembler-arch    : list available assembler archs\n'
		msg += '    !list-disassembler-arch : list available disassembler archs\n'
		msg += '    !d.ARCH OPCODES         : disassemble opcodes\n'
		msg += '        example: !d.arm \\x10\\x00\\xa0\\xe3\\x00\\x10\\xa0\\xe1\n'
		msg += '    !a.ARCH ASM             : assemble assembly\n'
		msg += '        example: !a.arm mov r0,0x10; mov r1, r0\n'
		self.send_msg(dest,msg)

	def assemble(self,opcodes,arch):
		try:
			ks = Ks(arch["KS_ARCH"], arch["KS_MODE"])
			encoding, count = ks.asm(opcodes)
			out=""
			if count > 0 and encoding != None:
				for i in encoding:
					out+="\\x%02x" % i
			if count > 0 and encoding != None:
				out+="\n"
			if count > 0 and encoding != None:
				for i in encoding:
					out+="%02x " % i
			return out
		except KsError as e:
			return "ERROR : %s" % (e)

	def disassemble(self,bin_bytes,arch):
		try:
			out=""
			md = Cs(arch["CS_ARCH"], arch["CS_MODE"])
			for i in md.disasm(bin_bytes,0):
				out+="%s %s; " % (i.mnemonic,i.op_str)
			return out
		except CsError as e:
			return "ERROR : %s" % (e)

	def handle_msg(self, dest, msg):
		if msg == "!help":
			return self.__send_help(dest)
		if msg == "!list-assembler-arch":
			return self.__send_assembler_archlist(dest)
		if msg == "!list-disassembler-arch":
			return self.__send_disassembler_archlist(dest)

		if msg.startswith("d.") or msg.startswith("a."):
			arch=""
			opcodes=""
			try:
				# TODO rewrite THIS !
				action = msg.split(".")[0]
				arch = msg.split(".")[1].split(" ")[0]
				opcodes = " ".join(msg.split(" ")[1:])
			except:
				self.send_msg(dest,"Error: Can't parse arguments %s" % (msg))
				return
			if arch is None or opcodes is None or arch == "" or opcodes == "":
				self.send_msg(dest,"Error: Can't parse arguments %s" % (msg))
				return
			if action == "d":
				if arch in self.supported_capstone_archs.keys():
					bin_opcodes=""
					try:
						if "\\x" in opcodes:
							bin_opcodes = str(literal_eval("'"+opcodes+"'"))
						else:
							bin_opcodes = opcodes.replace(" ","").decode("hex")
					except:
						self.send_msg(dest,"Error: Can't convert '%s' to bytes" % (opcodes))
						return
					resp = self.disassemble(bin_opcodes,self.supported_capstone_archs[arch])
					self.send_msg(dest,resp)
					return
				else:
					self.send_msg(dest,"Error: unsupported arch %s" % (arch))
					return
			if action == "a":
				if arch in self.supported_keystone_archs.keys():
					resp = self.assemble(opcodes,self.supported_keystone_archs[arch])
					self.send_msg(dest,resp)
					return
				else:
					self.send_msg(dest,"Error: unsupported arch %s" % (arch))
					return


if __name__ == "__main__":
	bot = botCli()
	bot.handle_msg(None," ".join(sys.argv[1:]))
