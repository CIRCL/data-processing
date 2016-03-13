#!/usr/bin/env python
# -*- coding: utf-8 -*-

from redis import StrictRedis
from helper import dict_to_md


r = StrictRedis(port=6399)

use_subset = True

event_by_cve = {}

for uuid in r.smembers('events'):
    if use_subset and uuid not in r.smembers('subset'):
        continue
    cves = r.smembers('event:{}:cve'.format(uuid))
    if not cves:
        continue
    for cve in cves:
        if not event_by_cve.get(cve):
            event_by_cve[cve] = []
        data = r.hgetall('event:{}'.format(uuid))
        event_by_cve[cve].append([data['eid'], data['date'], data['info']])

dict_to_md(event_by_cve)
