from __future__ import division, print_function
import sys, time, os

#
#Title: Crackme #3 by S!x0r Key Generator/Solution
#Author: Jacob Holcomb, Senior Security Analyst @ ISE
#Twitter: @rootHak42
#Date: March 2016
#URL: crackmes.de/users/sx0r/crackme3_by_sx0r/
#

def div(edx, eax, esi):
		mod = ((edx << 32) | eax) % esi
		eax = ((edx << 32) | eax) // esi
		edx = mod
		return edx, eax

def mul(reg, edx, eax):
		edx = ((reg * eax) & (0xFFFFFFFF << 32)) >> 32
		eax = (reg * eax) & 0xFFFFFFFF
		return edx, eax

def sub_8048270(esi, edi, edx, ecx, ebx):
	edi = 0x1
	while True:
		if hex(ecx) == hex(0x0):
			eax = edi
			return eax

		edx = ecx
		edx = 0x1 & edx
	
		if hex(0x0) != hex(edx):
			eax = edi
			edx, eax = mul(ebx, edx, eax) 
			edx, eax = div(edx, eax, esi)
			edi = edx

		ecx = ecx >> 1
		eax = ebx
		edx, eax = mul(ebx, edx, eax)
		edx, eax = div(edx, eax, esi)
		ebx = edx #0x08048296

def float_pt_func(addr_one_val, addr_two_val, addr_three_val):
	eax = None
	#ST registers are loaded using push/pop.
	#fildll instructions
	st0 = addr_two_val
	st1 = addr_one_val

	#fmulp st, st1
	fmulp = st0 * st1
	#returning product of mult to st1 and then FP stack pop
	#which results in the product being stored in st0
	st0 = fmulp
	
	#fildll instruction. Remember push/pop
	st1 = st0
	st0 = addr_three_val

	#fxch exchanges values of supplied ST register (in this case st1) w/ st0
	tmp_st0 = st0
	st0 = st1
	st1 = tmp_st0

	#fprem takes remainder of st0 % st1 and stored in st0
	st0 = st0 % st1

	#fistl converts value in st0 to signed int and stores result
	addr_three_val = int(st0)

	#prepare return value
	eax = addr_three_val
	return eax, addr_three_val
	
def str_int_conv(str_text, base):
		converted_int = int(str_text, base)
		return converted_int

def username_multiply(name):
	edx = 0x7e4c9e32
	esi = name
	eax = None
	for char in esi:
		eax = ord(char)
		edx = eax * edx
	edx = edx & 0xFFFFFFFF#Chopping the high order bytes off
	return edx	

def clear():
	platform = sys.platform
	if "win" == platform[0:3]:
		os.system("cls")
	else:	
		os.system("tput reset")
	return

def main():
	#Flush terminal
	clear()
	#Keep track of program runtime
	start_time = time.time()
	date_time = time.gmtime(start_time)
	chk_time = 5.0
	greeting = """S!x0r Crackme3 Keygen by Gimppy/rootHak42.\n\n[*] Generating serial number for {0}.\n[*] Program start time: {1}.\n[*] Hang tight...\n
			   """.format(sys.argv[1], time.asctime(date_time))
	print(greeting)

	eax = 0x0
	ebx = 0x0 #Frst run should last 4 of serial convereted to int
	ecx = 0x0
	edx = 0x0
	edi = 0x0
	esi = 0x0

	#0x80494XX (where XX byte is the number in var name below)
	mem_loc_10 = 0x0
	mem_loc_70 = 0x0
	mem_loc_80 = 0x0
	mem_loc_90 = 0x0
	mem_loc_20 = 0x0
	mem_loc_30 = 0x0
	mem_loc_50 = 0x0
	mem_loc_60 = 0x0

	hex_str = 0x20000000#0xffffffff#0x13390000

	edx = username_multiply(sys.argv[1])
	dword_80493E0 = edx#Result of multiplicaiton/NL check on username.

	while hex_str != 0x00000000:
		cur_time = time.time()
		run_time = round(cur_time - start_time)
		if run_time == chk_time:
			clear()
			print(greeting)
			print("Total Program Run Time: {0} seconds.\n".format(run_time))
			chk_time += 5.0
 
		serial = hex(hex_str)
		serial = serial[2:6] + "-" + serial[6:]

		#Variables to store int version of str/ascii
		serial_int_one = str_int_conv(serial[:4], 16)#0x80493f0
		serial_int_two = str_int_conv(serial[5:], 16)#0x8049400
		
		#Call first x86 routine to perform math on 2nd half of converted serial number
		ebx = serial_int_two
		eax = 0x1
		ecx = 0xf2a7
		ecx = ecx - 2 #0xf2a5
		esi = 0xf2a7
		ret_to_eax = sub_8048270(esi, edi, edx, ecx, ebx)
		mem_loc_10 = ret_to_eax #Move return value to memory location
		mem_loc_70 = mem_loc_10 #Storing value in another memory location

		eax = dword_80493E0
		mem_loc_80 = eax#This value should actually be the result of mult/NL check of username
		mem_loc_90 = 0xf2a7 #0x080481C8
		ebx += 0x1b69 #adjust ebx to match CPU register
		ecx = 0x0 #adjust ecx to match CPU register

		ret_to_eax, mem_loc_90 = float_pt_func(mem_loc_70, mem_loc_80, mem_loc_90)
		eax = ret_to_eax
		mem_loc_20 = eax

		eax = serial_int_one
		mem_loc_70 = eax
		eax = mem_loc_10
		#EDX and EDI are not correct at this point, but it doesn't matter
		mem_loc_80 = eax
		mem_loc_90 = 0xf2a7

		#Calling FP Function
		ret_to_eax, mem_loc_90 = float_pt_func(mem_loc_70, mem_loc_80, mem_loc_90)
		eax = ret_to_eax
		mem_loc_30 = eax
		ebx = 0x15346
		ecx = mem_loc_20
		esi = 0x3ca9d

		ret_to_eax = sub_8048270(esi, edi, edx, ecx, ebx)
		eax = ret_to_eax
		mem_loc_50 = eax
		ebx = 0x307c7
		ecx = mem_loc_30
		esi = 0x3ca9d

		ret_to_eax = sub_8048270(esi, edi, edx, ecx, ebx)
		eax = ret_to_eax
		mem_loc_60 = eax
		mem_loc_70 = eax
		eax = mem_loc_50
		mem_loc_80 = eax
		mem_loc_90 = 0x3ca9d

		ret_to_eax, mem_loc_90 = float_pt_func(mem_loc_70, mem_loc_80, mem_loc_90)
		eax = ret_to_eax
		edx = edx ^ edx
		edi = 0xf2a7
		edx = eax % edi
		eax = eax // edi
		#EBX and ECX are wrong, but it doesn't matter.

		if serial_int_one == edx:
			end_time = time.time()
			run_time = round(cur_time - start_time)
			serial_msg = """[*] Generator Exiting.\n[*] Serial Generated in {0} seconds.\n[*] Generated Serial: {1}\n\n
						 """.format(run_time, serial)
			print(serial_msg)
			sys.exit(0)

		hex_str = hex_str - 1

if __name__ == "__main__":
	main()
