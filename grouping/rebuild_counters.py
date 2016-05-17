#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import redis
from ConfigParser import SafeConfigParser

if __name__ == '__main__':

    parser = argparse.ArgumentParser('Rebuild all the ranked sets')
    parser.add_argument("-c", "--config", default='correlator.conf', help="Configuration file.")
    args = parser.parse_args()

    config = SafeConfigParser()
    config.read(args.config)

    r = redis.StrictRedis(host=config.get('redis', 'host'), port=config.get('redis', 'port'))

    r.delete('timestamps', 'imphashs', 'entrypoints', 'secnumbers', 'originalfilenames')

    p = r.pipeline(False)
    for h in r.smembers('hashes_sha256'):
        data = r.hgetall(h)
        if not data.get('is_pefile'):
            continue
        if data.get('timestamp_iso'):
            p.zincrby('timestamps', data['timestamp_iso'])
        if data.get('imphash'):
            p.zincrby('imphashs', data['imphash'])
        if data.get('entrypoint'):
            p.zincrby('entrypoints', data['entrypoint'])
        if data.get('secnumber'):
            p.zincrby('secnumbers', data['secnumber'])
        if data.get('originalfilename'):
            p.zincrby('originalfilenames', data['originalfilename'])
    p.execute()
