#!/usr/bin/env python
# -*- coding: utf-8 -*-

from collections import Counter


def dict_to_md(mydict):
    for key, value in sorted(mydict.items(), key=lambda x: x[0]):
        print '#', key
        print
        s = [', '.join(v) for v in sorted(value, key=lambda x: x[0])]
        counted = Counter(s)
        for entry, count in counted.items():
            print '*', entry, '({})'.format(count)
        print
