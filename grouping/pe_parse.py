#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pefile
import datetime
import math
import argparse
import redis
try:
    from configparser import SafeConfigParser
except ImportError:
    # Python2
    from ConfigParser import SafeConfigParser


# Return section ID and name of EP section in the form name|id
def check_ep_section(pe):
    name = ''
    if hasattr(pe, 'OPTIONAL_HEADER'):
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    else:
        return False
    pos = 0
    for sec in pe.sections:
        if (ep >= sec.VirtualAddress) and (ep < (sec.VirtualAddress + sec.Misc_VirtualSize)):
            name = sec.Name.decode('utf-8', 'ignore').replace('\x00', '')
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


def get_attr_pe(r, sha256):
    path = r.hget(sha256, 'path')
    try:
        pe = pefile.PE(path)
    except (pefile.PEFormatError):
        print("{} not a PE file".format(path))
        return False

    r.hset(sha256, 'is_pefile', True)

    if hasattr(pe, 'FILE_HEADER'):
        r.hset(sha256, 'timestamp', pe.FILE_HEADER.TimeDateStamp)
        r.hset(sha256, 'timestamp_iso', datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat())
        r.zincrby('timestamps', pe.FILE_HEADER.TimeDateStamp)
        r.sadd('timestamp:{}'.format(pe.FILE_HEADER.TimeDateStamp), sha256)

    imphash = pe.get_imphash()
    r.hset(sha256, 'imphash', imphash)
    r.zincrby('imphashs', imphash)
    r.sadd('imphash:{}'.format(imphash), sha256)

    if hasattr(pe, 'OPTIONAL_HEADER'):
        r.hset(sha256, 'entrypoint', pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        r.zincrby('entrypoints', pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        r.sadd('entrypoint:{}'.format(pe.OPTIONAL_HEADER.AddressOfEntryPoint), sha256)

    if hasattr(pe, 'FILE_HEADER'):
        r.hset(sha256, 'secnumber', pe.FILE_HEADER.NumberOfSections)
        r.zincrby('secnumbers', pe.FILE_HEADER.NumberOfSections)
        r.sadd('secnumber:{}'.format(pe.FILE_HEADER.NumberOfSections), sha256)

    if hasattr(pe, 'VS_VERSIONINFO'):
        for entry in pe.FileInfo:
            if hasattr(entry, 'StringTable'):
                for st_entry in entry.StringTable:
                    ofn = st_entry.entries.get('OriginalFilename')
                    if ofn:
                        r.hset(sha256, 'originalfilename', ofn)
                        r.zincrby('originalfilenames', ofn)
                        r.sadd(u'originalfilename:{}'.format(ofn), sha256)

    # Section info: names, sizes, entropy vals
    for section in pe.sections:
        name = section.Name.decode('utf-8', 'ignore').replace('\x00', '')
        r.sadd('{}:secnames'.format(sha256), name)
        r.hset('{}:{}'.format(sha256, name), 'size', section.SizeOfRawData)
        r.hset('{}:{}'.format(sha256, name), 'entropy', H(section.get_data()))

    # adding section info to PE data
    r.hset(sha256, 'nb_tls', check_tls(pe))
    r.hset(sha256, 'ep_section', check_ep_section(pe))
    return True


# Returns Entropy value for given data chunk
def H(data):
    if not data:
        return 0

    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def eval_packed(r, sha256):
    sha256_val = r.hgetall(sha256)
    packed_value = 0
    standard_ep_section_names = ['.text|0', '.itext|1', 'CODE|0']
    if sha256_val['ep_section'] not in standard_ep_section_names:
        packed_value += 90
    if int(sha256_val['secnumber']) < 3:
        packed_value += 20
    if int(sha256_val['nb_tls']) > 0:
        packed_value += 20
    if not sha256_val['imphash']:
        packed_value += 10

    for secname in r.smembers('{}:secnames'.format(sha256)):
        if 6.0 < float(r.hget('{}:{}'.format(sha256, secname), 'entropy')) < 6.7:
            packed_value += 50

    r.hset(sha256, 'packed', packed_value)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parse one PE File')
    parser.add_argument("-c", "--config", default='correlator.conf', help="Configuration file.")
    parser.add_argument("filehash", help="File's hash to parse.")
    args = parser.parse_args()

    config = SafeConfigParser()
    config.read(args.config)

    r = redis.StrictRedis(host=config.get('redis', 'host'), port=config.get('redis', 'port'), decode_responses=True)

    if get_attr_pe(r, args.filehash):
        eval_packed(r, args.filehash)
