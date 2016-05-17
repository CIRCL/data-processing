#!/usr/bin/env python
# -*- coding: utf-8 -*-

from redis import StrictRedis
import sys
import csv

writer = csv.writer(sys.stdout)

r = StrictRedis(port=6399)

all_hashes = r.smembers('hashes_sha256')

while all_hashes:
    cur_hash = all_hashes.pop()
    zrange = r.zrevrange('matches_{}'.format(cur_hash), 0, -1, True)
    if not zrange:
        continue
    cur_ssdeep = r.hget(cur_hash, 'ssdeep')
    cur_eids = r.smembers('{}:eids'.format(cur_hash)).union(r.smembers('{}:eids'.format(r.hget(cur_hash, 'md5')))).union(r.smembers('{}:eids'.format(r.hget(cur_hash, 'sha1'))))
    uuids = [r.get('eventuuid:{}'.format(eid)) for eid in cur_eids]
    infos = [r.hget('event:{}'.format(uuid), 'info') for uuid in uuids]
    eids_infos = zip(cur_eids, infos)
    cur_list = []
    for h, score in zrange:
        if h in all_hashes:
            all_hashes.remove(h)
        if score > 90:
            eids = r.smembers('{}:eids'.format(h)).union(r.smembers('{}:eids'.format(r.hget(h, 'md5')))).union(r.smembers('{}:eids'.format(r.hget(h, 'sha1'))))
            uuids = [r.get('eventuuid:{}'.format(eid)) for eid in eids]
            infos = [r.hget('event:{}'.format(uuid), 'info')for uuid in uuids]
            ssdeep = r.hget(h, 'ssdeep')
            cur_list.append([h, ssdeep, zip(eids, infos)])
    if cur_list:
        cur_printed = False
        for h, s, eids in cur_list:
            for eid, info in eids:
                if eid not in cur_eids:
                    if not cur_printed:
                        print cur_hash, cur_ssdeep, eids_infos
                        cur_printed = True
                    print h, s, eid, info
        if cur_printed:
            print '\n'
