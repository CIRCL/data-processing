#!/usr/bin/env python
# encoding: utf-8


import os
import hashlib
import time
#import exiftool
import pefile
import subprocess
import math
import string
#import Database
import argparse
import platform
from ctypes import cdll, create_string_buffer

# CONSTANT FOR SSDEEP HASH LENGTH
FUZZY_MAX_RESULT = (2 * 64 + 20)

# MODULES HERE:

# MD5 and general hash calculation
# ssdeep
# imphash
# pefile
# exiftool

# EP section, section count, names, entropy, size
# IDAPython data generation, get call count, CallsPerKB, DistinctCallsPerKB

# IMPORTANT DETAILS:
# names of files to be parsed should be hashes - any hash - no . should be contained


# Return general data of a sample
def generalDataMe(dirpath, filename):
	path = os.path.join(dirpath, filename)
	content = file(path, 'rb').read()
	result = []
	dirname = dirpath.split(os.path.sep)[-1]
	result.append(hashlib.md5(content).hexdigest())
	result.append(hashlib.sha1(content).hexdigest())
	result.append(dirname)
	result.append(filename)
	return result


# Return ssdeep hash of a sample
if platform.release() != 'Linux':
	def ssdeepMe(path):
		# Load ssdeep lib
		ssdeepdll = cdll.LoadLibrary(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'fuzzy.dll'))

		if path is not None:
			result = create_string_buffer(FUZZY_MAX_RESULT)
			ssdeepdll.fuzzy_hash_filename(path, result)
			return result.value
		else:
			print("Ssdeep: provide a file path")
			return ""

elif platform.release() == 'Linux':
	import pydeep

	def ssdeepMe(path):
		if path is not None:
			return pydeep.hash_file(path)
		else:
			print("Ssdeep: provide a file path")
			return ""


# Return list of attributes extracted from pefile: EP, Num Sections, original file name, entropy data, imphash, TLS data, EP section name
def pefileMe(path):

	if path is None:
		print("Pefile: provide a file path")
		return ""

	try:
		pe = pefile.PE(path)
		pefilelist = []
		sects = []
		vadd = []
		ent = []

		# PE Timestamp, Imphash, Address EP, Section Count and OriginalFilename
		pefilelist.append(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(pe.FILE_HEADER.TimeDateStamp)))
		pefilelist.append(pe.get_imphash())
		pefilelist.append(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
		secnumber = pe.FILE_HEADER.NumberOfSections
		pefilelist.append(secnumber)

		oriFilename = ""
		if hasattr(pe, 'VS_VERSIONINFO'):
			if hasattr(pe, 'FileInfo'):
				for entry in pe.FileInfo:
					if hasattr(entry, 'StringTable'):

						for st_entry in entry.StringTable:
							for str_entry in st_entry.entries.items():
								if 'OriginalFilename' in str_entry:
									# UGLY DIRTY TRICK to sanitize values
									try:
										oriFilename = str(str_entry[1].decode("ascii", "ignore"))
									except:
										oriFilename = "PARSINGERR"
		pefilelist.append(oriFilename)

		# Section info: names, sizes, entropy vals

		for i in range(6):

			if (i + 1 > secnumber):
				strip = ""
				strap = ""
				entropy = ""

			else:
				stuff = pe.sections[i]
				strip = stuff.Name.replace('\x00', '')
				strap = str(stuff.SizeOfRawData).replace('\x00', '')

				entropy = H(stuff.get_data())

			section_name = ""
			try:
				section_name = strip.decode("ascii", "ignore")
			except:
				section_name = "PARSINGERR"

			sects.append(section_name)
			ent.append(entropy)
			if strap.isdigit():
				vadd.append(int(strap))
			else:
				vadd.append('')

		# adding section info to PE data
		pefilelist = pefilelist + sects + vadd + ent
		pefilelist.append(check_tls(pe))
		pefilelist.append(check_ep_section(pe))

		return pefilelist
	except (pefile.PEFormatError):
		print("%s not a PE file" % path)
		return []
	except (AttributeError) as e:
		print("Other exception with %s" % path)
		print(str(e))
		return []
	except (Exception) as e:
		print("Error %s" % str(e))
		return []


# Return info from Exiftool, such as file type and file size
def exiftoolMe(path):

	# exiftool is the lazy solution here but no other decent (known) tool to determine file types on Windows detailed (!) and reliable
	if platform.release() != 'Linux':

		pathtoexif = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'exiftool696.exe')

		with exiftool.ExifTool(pathtoexif) as et:

			# TO INSPECT WHAT ELSE EXIF DELIVERS:
			# metadata = et.get_metadata(path)
			# print "\n\n"
			# for d in metadata:
			#   print d,"\t\t\t", et.get_tag(d, path)
			to_return = []

			# if driver, replace filetype
			try:
				pe = pefile.PE(path)
				if (pefile.SUBSYSTEM_TYPE[pe.OPTIONAL_HEADER.Subsystem] == 'IMAGE_SUBSYSTEM_NATIVE'):
					to_return.append('WIN32 SYS')
				else:
					to_return.append(et.get_tag('File:FileType', path))
			except:
				to_return.append(et.get_tag('File:FileType', path))
			to_return.append(et.get_tag('File:FileSize', path))
			return to_return
	else:
		to_return = []
		to_return.append('')
		to_return.append('')


# Call IDAPython magic script, write packer data directly to DB
def idaPythonMe(path):
	# In order to get that stuff to run - only static paths, sorry - modify accordingly
	subprocess.call([r'C:\Program Files (x86)\IDA 6.9\idaq64.exe', '-A', r'-OIDAPython:1;Y:\TroopersPrez\SampleParsing\Idapythonmagic.py', path])


# RETURNS AN ITERABLE - SEARCH FOR STRINGS OR PATTERNS IN STRINGS IN BINARY
def stringsMe(path, min=4):
	with open(path, "rb") as f:
		res = ""
		for c in f.read():
			if c in string.printable:
				res += c
				continue
			if len(res) >= min:
				yield res
			res = ""


# Returns Entropy value for given data chunk
def H(data):
	if not data:
		return 0

	entropy = 0#
	for x in range(256):
		p_x = float(data.count(chr(x))) / len(data)
		if p_x > 0:
			entropy += - p_x * math.log(p_x, 2)

	return entropy


# Return section ID and name of EP section in the form name|id
def check_ep_section(pe):
	name = ''
	ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	pos = 0
	for sec in pe.sections:
		if (ep >= sec.VirtualAddress) and \
		   (ep < (sec.VirtualAddress + sec.Misc_VirtualSize)):
			name = sec.Name.replace('\x00', '')
			name = name.decode("ascii", "ignore")
			break
		else:
			pos += 1
	return (name + "|" + pos.__str__())


# Return number of TLS sections found
def check_tls(pe):
	idx = 0
	if (hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS and
	   pe.DIRECTORY_ENTRY_TLS.struct and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks):
		callback_array_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase

		while True:
			func = pe.get_dword_from_data(pe.get_data(callback_array_rva + 4 * idx, 4), 0)
			if func == 0:
				break
			idx += 1
	return idx


def check_pe_header(filepath):
	try:
		pe = pefile.PE(filepath)
		if (pe.DOS_HEADER.e_magic == int(0x5a4d) and pe.NT_HEADERS.Signature == int(0x4550)):
			return True
	except (pefile.PEFormatError):
		return False
	except(Exception) as e:
		print("LOG - Something weird %s - %s" % (str(e), filepath))
		return False
	return False


if __name__ == '__main__':

	# setup option parser
	parser = argparse.ArgumentParser(description='Generate database')
	parser.add_argument("-i", "--init", help="Initialize create DB and parse event info from file, requries path to event info file")
	parser.add_argument("-d", "--dir", help="Parse malware directory")
	parser.add_argument("-s", "--strings", action="store_true", help="Iterate through strings in files TODO")
	parser.add_argument("-f", "--flush", action="store_true", help="Flushes content form all but Events table")
	parser.add_argument("-p", "--packed", action="store_true", help="Evaluate PE packer data, sets packed attribute in SamplePeData table")
	parser.add_argument("-m", "--msdetections", help="Adds Microsoft detection names to Samples table, requires Defender to be on the machine, expects directory of samples as argument.")
	parser.add_argument("-y", "--idapython", help="Runs IDAPYthon (make sure the paths in the script are adapted) to extracts API call info for packer detection")

	args = parser.parse_args()

	if args.init:
		# init DB
		# open and read event file
		# parse to Events table

		db = Database.Database()
		db.flush_all()
		db.create_scheme()

		with open(args.init, 'r') as f:
			for entry in f:
				line = entry.split('-')
				event_id = line[0]
				comment = line[1]
				db.insert_event(event_id.strip(), comment.strip())

	if args.dir:

		# parse directory for general data, pe file data and packer data
		db = Database.Database()

		for (dirpath, dirnames, filenames) in os.walk(args.dir):
			for filename in filenames:

				if '.' not in filename:

					generalList = []
					filepath = os.path.join(dirpath, filename)

					# generalDataMe
					# ssdeepMe
					# exiftoolMe

					# md5, sha1, dirname (=tag), filename
					for item in generalDataMe(dirpath, filename):
						generalList.append(item)

					# check whether that sample in this same event already exists and whether the event is valid
					if (db.check_sample(generalList[0], generalList[2]) == 0 and db.event_exists(generalList[2]) != 0): # md5, tag

						# fileType, fileSize
						for item in exiftoolMe(filepath):
							generalList.append(item)

						generalList.append(ssdeepMe(filepath))

						# TODO:
						# msDetecion, comment

						db.insert_sample(generalList[0], generalList[1], generalList[2], generalList[3], generalList[4], generalList[5], generalList[6], "", "")

						# pefileMe
						if (db.check_pe_data(generalList[0]) == 0):

							peList = []
							if check_pe_header(filepath):

								# names x6, sizes x6, entropy x6, number TLS sections, EP section name | id

								for item in pefileMe(filepath):
									peList.append(item)

								if peList:
									db.insert_sample_pe_data(generalList[0], peList[0], peList[1], peList[2], peList[3], peList[4],  # MD5, PE Timestamp, imphash, address EP, section count, original filename,
															 peList[5], peList[6], peList[7], peList[8], peList[9], peList[10],	   # Section names
															 peList[11], peList[12], peList[13], peList[14], peList[15], peList[16],	 # Section sizes
															 peList[17], peList[18], peList[19], peList[20], peList[21], peList[22],	 # Section entropies
															 peList[23], peList[24])													 # TLS sections, EP section name + id

									# <legacycode>
									idaPythonMe(filepath)
									# </legacycode>

								else:
									print("LOG - Error parsing PE file %s" % filename)

								try:
									idb = filepath + ".idb"
									os.remove(idb)
								except:
									pass
								try:
									idb = filepath + ".i64"
									os.remove(idb)
								except:
									pass

						print("LOG - Done with %s" % filename)
					else:
						print("LOG - Sample with this Event already in DB %s, or Event invalid %s" % (filename, generalList[2]))
					# stringsMe
					# hashMe

	if args.idapython:

		db = Database.Database()

		for (dirpath, dirnames, filenames) in os.walk(args.idapython):
			for filename in filenames:
				if '.' not in filename:
					filepath = os.path.join(dirpath, filename)
					md5 = hashlib.md5(open(filepath, 'rb').read()).hexdigest()
					if (db.check_apistats(md5) == 0):
						idaPythonMe(filepath)

	if args.strings:
		print "Left as a TODO on wishlist!"

	if args.flush:
		db = Database.Database()
		db.flush_sample_data()

	if args.packed:
		# Calculate 'packed' attribute based on:
		# EP section not normal
		# entropy of EP section > 6,7 ?
		# section names contain keyword
		# api call ratio below threshold

		db = Database.Database()

		cursor = db.get_pe_packerdata()
		while True:
			rows = cursor.fetchmany(100)
			if not rows: break
			for item in rows:
				eval = 0
				md5 = item[0]
				imphash = item[1]
				sectionCount = item[2]
				numberTls = item[3]
				epSection = item[4]
				if item[5]:
					apiCallRatio = float(item[5])
				else:
					apiCallRatio = None

				# sqlite rows dont support slicing....
				secNames = []
				secEntropies = []

				i = 6
				while i<=11:
					secNames.append(item[i])
					i = i+1
				while i<=17:
					secEntropies.append(item[i])
					i = i+1

				# some testing showed, samples with different EP sections are likely packed
				standard_ep_section_names = ['.text|0', '.itext|1', 'CODE|0']

				if epSection not in standard_ep_section_names:
					eval = eval + 90
				if apiCallRatio is not None and apiCallRatio < 0.1:
					eval = eval + 40
				if sectionCount < 3:
					eval = eval + 20
				if numberTls > 0:
					eval = eval + 20
				if not imphash:
					eval = eval + 10
				if float(secEntropies[0]) > 6.7 or float(secEntropies[0]) < 6.0:
					eval = eval + 50

				epSecIndex = epSection.split('|')[1]
				# max. 6 secEntropies available
				if epSecIndex <=6:
					if float(secEntropies[epSecIndex]) > 6.7 or float(secEntropies[epSecIndex]) < 6.0:
						eval = eval + 60

				db.update_packed(md5, eval)

	if args.msdetections:

		db = Database.Database()

		samplepath = args.msdetections

		# not thoroughly tested, change as needed
		defenderpath = os.getenv('ProgramW6432')
		scanme = r'"' + defenderpath + r'\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File ' + samplepath + ' -DisableRemediation'

		try:
			output = subprocess.Popen(scanme, stdout=subprocess.PIPE).communicate()[0]

			myThreat = ''
			myFile = ''

			output = output.splitlines()
			for line in output:
				if line.startswith('Threat'):
					myThreat = line.split(' : ')[1].strip()
				if ' file' in line.split(' : ')[0]:
					myFile = line.split(' : ')[1].strip()
					myFile = myFile.split('-')[0]

					content = file(myFile, 'rb').read()
					myMd5 = hashlib.md5(content).hexdigest()

					db.update_msdetection(myMd5, myThreat)

		except(Exception) as e:
			print("Error %s " % (str(e)))
			print "Sure u got Defender on here?"
