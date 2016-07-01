#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import os
import argparse
import redis
try:
    from configparser import SafeConfigParser
except ImportError:
    # Python2
    from ConfigParser import SafeConfigParser

from subprocess import Popen, PIPE
import csv
import sys
import pydeep
import time
from Crypto.Hash import SHA256


def import_dir(directory, r):
    p = r.pipeline(False)
    md5s = []
    sha1s = []
    sha256s = []
    for (dirpath, dirnames, filenames) in os.walk(args.dir):
        for filename in filenames:
            path = os.path.join(dirpath, filename)
            content = open(path, 'rb').read()
            md5 = hashlib.md5(content).hexdigest()
            sha1 = hashlib.sha1(content).hexdigest()
            sha256 = hashlib.sha256(content).hexdigest()
            ssdeep = pydeep.hash_buf(content)
            md5s.append(md5)
            sha1s.append(sha1)
            sha256s.append(sha256)
            p.hmset(sha256, {'md5': md5, 'sha1': sha1, 'filename': filename, 'path': path, 'ssdeep': ssdeep})
    p.execute()
    return md5s, sha1s, sha256s


def search_misp_values(r, values, return_eventid=True):
    to_search = ['hashstore:{}'.format(SHA256.new(v.lower()).hexdigest()) for v in values]
    uuid_by_hashes = [r.smembers(k) for k in to_search]
    if not return_eventid:
        return uuid_by_hashes
    to_return = []
    for h in uuid_by_hashes:
        to_return.append([r.hget('uuid_id', uuid) for uuid in h])
    return to_return

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate database')
    parser.add_argument("-c", "--config", default='correlator.conf', help="Configuration file.")
    parser.add_argument("-d", "--dir", help="Directory contianing the malwares")
    parser.add_argument("-e", "--events", action="store_true", help="List all the event IDs where the hashes are seen")
    parser.add_argument("-p", "--pe", action="store_true", help="Process all files with pefile")
    parser.add_argument("--dump", action="store_true", help="Dump all the correlations")
    args = parser.parse_args()

    config = SafeConfigParser()
    config.read(args.config)

    r = redis.StrictRedis(host=config.get('redis', 'host'), port=config.get('redis', 'port'), decode_responses=True)

    if args.dir:
        md5, sha1, sha256 = import_dir(args.dir, r)
        r.sadd('hashes_md5', *md5)
        r.sadd('hashes_sha1', *sha1)
        r.sadd('hashes_sha256', *sha256)

    elif args.events:
        misp_url = config.get('fast-lookup', 'misp_url')
        webservice_url = config.get('fast-lookup', 'webservice_url')
        authkey = config.get('fast-lookup', 'authkey')
        eids = search_misp_values(r, list(r.smembers('hashes_md5')))
        correlations = list(zip(r.smembers('hashes_md5'), eids))
        eids = search_misp_values(r, list(r.smembers('hashes_sha1')))
        correlations += list(zip(r.smembers('hashes_sha1'), eids))
        eids = search_misp_values(r, list(r.smembers('hashes_sha256')))
        correlations += list(zip(r.smembers('hashes_sha256'), eids))
        for h, eids in correlations:
            if not eids:
                continue
            r.sadd('{}:eids'.format(h), *eids)
    elif args.pe:
        p = Popen(['parallel', './pe_parse.py', '-c', args.config], stdout=PIPE, stdin=PIPE, stderr=PIPE, universal_newlines=True)
        out, err = p.communicate(input='\n'.join(r.smembers('hashes_sha256')))
        while p.poll() is None:
            time.sleep(1)
        print(err)
    if args.dump:
        writer = csv.writer(sys.stdout)
        all_hashes = r.smembers('hashes_md5').union(r.smembers('hashes_sha1')).union(r.smembers('hashes_sha256'))
        for h in all_hashes:
            eids = r.smembers('{}:eids').format(h)
            if eids:
                writer.writerow([h] + eids)
