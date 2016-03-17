#!/usr/bin/env python
# encoding: utf-8

from idautils import *
from idc import *
import sys
from idaapi import *
# import sqlite3
from hashlib import md5

import Database

# ## Walk the functions

idaapi.autoWait()

mypath = GetInputFilePath()
mymd5 = md5(open(mypath, 'rb').read()).hexdigest()

# For Troopers project, containing folder is equivalent to eventid
pathsplitted = mypath.split('\\')
#eventid = pathsplitted[len(pathsplitted) - 2]

if (len(sys.argv) > 1):
    packertag = str(sys.argv[1])

db = Database.Database()

calls = dict()

for segment_effective_address in Segments():

    for head in Heads(segment_effective_address, SegEnd(segment_effective_address)):

        if isCode(GetFlags(head)):

            # Disassemble every line
            mnem = GetDisasm(head)

            if mnem[:4] == 'call' and 'sub_' not in mnem and 'loc_' not in mnem and 'dword ptr' not in mnem:

                # If call to function with symbol - sanitize and add to counter
                mycall = str(mnem).replace(';', '')
                calls[mycall] = calls.get(mycall, 0) + 1


for call in calls.keys():

    # Persist call to database
    db.insert_call(mymd5, call, int(str(calls[call])))

if not calls.keys():
    db.insert_call(mymd5, "none", 0)

idc.Exit(0)
