#!/usr/bin/env python
# -*- coding: utf-8 -*-

from redis import StrictRedis
import csv

pe_indicators = ['timestamps', 'imphashs', 'entrypoints', 'originalfilenames', 'secnumbers']
r = StrictRedis(port=6399)

eid_ignore_list = set(['1813', '2862', '11', '63', '257'])


for i in pe_indicators:
    with open('{}.csv'.format(i), 'w') as f:
        writer = csv.writer(f)
        for key, score in r.zrevrange(i, 0, -1, True):
            if score == 1:
                continue
            hashes = r.smembers('{}:{}'.format(i[:-1], key))
            for h in hashes:
                md5 = r.hget(h, 'md5')
                sha1 = r.hget(h, 'sha1')
                eids = r.smembers('{}:eids'.format(md5)).union(r.smembers('{}:eids'.format(sha1))).union(r.smembers('{}:eids'.format(h)))
                eids = eids.difference(eid_ignore_list)
                if not eids:
                    continue
                writer.writerow([i, key, h, ','.join(sorted(eids, key=int))])
