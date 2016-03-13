#!/usr/bin/env python
# -*- coding: utf-8 -*-

from redis import StrictRedis
import csv

r = StrictRedis(port=6399)

names_by_events = {}
events_by_names = {}

for key, score in r.zrevrange('originalfilenames', 0, -1, True):
    if score == 1:
        continue
    hashes = r.smembers('{}:{}'.format('originalfilename', key))
    for h in hashes:
        md5 = r.hget(h, 'md5')
        sha1 = r.hget(h, 'sha1')
        eids = r.smembers('{}:eids'.format(md5)).union(r.smembers('{}:eids'.format(sha1))).union(r.smembers('{}:eids'.format(h)))
        for e in eids:
            if not names_by_events.get(e):
                names_by_events[e] = []
            names_by_events[e].append(key)
            if not events_by_names.get(key):
                events_by_names[key] = []
            events_by_names[key].append(e)

with open('names_by_events.txt', 'wb') as f:
    writer = csv.writer(f)
    keys = sorted(names_by_events.keys(), key=int)
    for k in keys:
        writer.writerow
        f.write('{}\t{}\n'.format(k, ', '.join(set(names_by_events.get(k)))))

with open('events_by_names.txt', 'wb') as f:
    keys = sorted(events_by_names.keys())
    for k in keys:
        f.write('{}\t{}\n'.format(k, ', '.join(set(events_by_names.get(k)))))

