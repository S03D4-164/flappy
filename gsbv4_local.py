#!/usr/bin/env python

from gglsbl import SafeBrowsingList
from gglsbl.protocol import URL
from gglsbl.utils import to_hex

import sys
import logging

def main():
    key = sys.argv[1]
    db = "../gsb_v4.db"
    platforms = ["WINDOWS"]
    sbl = SafeBrowsingList(key, db_path=db, platforms=platforms)
    #sbl.update_hash_prefix_cache()
    print(sbl.storage.get_threat_lists())

    url = sys.argv[2]
    u = URL(url)
    print(u.url)
    print(u.canonical)
    for i in u.url_permutations(u.canonical):
        print(i)
        print(u.digest(i))
    url_hashes = u.hashes
    print(url_hashes)

    full_hashes = list(url_hashes)
    print(full_hashes)

    cues = [to_hex(fh[0:4]) for fh in full_hashes]
    print(cues)

    print(sbl.storage.lookup_hash_prefix(cues))
    bl = sbl.lookup_url(url)
    print(bl)

if __name__ == '__main__':
    main()
