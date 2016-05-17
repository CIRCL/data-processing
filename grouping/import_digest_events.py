#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import csv
from redis import StrictRedis

r = StrictRedis(port=6399)


def import_events(path):
    with open(path, 'r') as f:
        reader = csv.reader(f)
        for eid, uuid, info, date, timestamp in reader:
            r.sadd('events', uuid)
            r.set('eventuuid:{}'.format(eid), uuid)
            r.sadd('eventids', eid)
            r.hmset('event:{}'.format(uuid), {'eid': eid, 'info': info, 'date': date, 'timestamp': timestamp})

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print('No path provided, do nothing.')
        sys.exit()
    import_events(sys.argv[1])
