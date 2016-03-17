# Introduction

This code aims to import files attributes and other event metadata from MISP into a local sqlite database.
IT runs on Window.

# Dependencies

* Pefile: https://github.com/erocarrera/pefile
* exiftool: http://www.sno.phy.queensu.ca/~phil/exiftool/ & https://github.com/smarnach/pyexiftool
* pydeep: http://ssdeep.sourceforge.net/usage.html#install
* idapython and IDA

# Usage


```
usage: Kinginyourcastle.py [-h] [-i INIT] [-d DIR] [-s] [-f] [-p]
                           [-m MSDETECTIONS] [-y IDAPYTHON]

Generate database

optional arguments:
  -h, --help            show this help message and exit
  -i INIT, --init INIT  Initialize create DB and parse event info from file,
                        requries path to event info file
  -d DIR, --dir DIR     Parse malware directory
  -s, --strings         Iterate through strings in files TODO
  -f, --flush           Flushes content form all but Events table
  -p, --packed          Evaluate PE packer data, sets packed attribute in
                        SamplePeData table
  -m MSDETECTIONS, --msdetections MSDETECTIONS
                        Adds Microsoft detection names to Samples table,
                        requires Defender to be on the machine, expects
                        directory of samples as argument.
  -y IDAPYTHON, --idapython IDAPYTHON
                        Runs IDAPYthon (make sure the paths in the script are
                        adapted) to extracts API call info for packer
                        detection

```

