#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import csv
from redis import StrictRedis

r = StrictRedis(port=6399)


def import_events(path):
    with open(path, 'r') as f:
        reader = csv.reader(f)
        for eid, cve in reader:
            uuid = r.get('eventuuid:{}'.format(eid))
            r.sadd('event:{}:cve'.format(uuid), cve)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('No path provided, do nothing.')
        sys.exit()
    import_events(sys.argv[1])
