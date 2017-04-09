#!/usr/bin/env pyton

import os, sys, re, logging
logging.basicConfig(level=logging.DEBUG)

#from flask import Flask, request, jsonify
#app = Flask(__name__)
from flask import request, jsonify
from . import routes

from configparser import ConfigParser
config = '../gsb.conf'
if not os.path.isfile(config):
    sys.exit('Config file not found.')

@routes.route('/gsb', methods=['GET'])
#@app.route('/gsb', methods=['GET'])
def lookup_db():
    from gglsbl import SafeBrowsingList
    from gglsbl.protocol import URL
    from gglsbl.utils import to_hex

    res = {}
    rdict = {
        'status':'',
        'message':'',
    }

    key = ''
    db = '../gsb_v4.db'
    platforms = ['WINDOWS']
    if os.path.isfile(config):
        cp = ConfigParser()
        cp.read(config)
        if 'api' in cp:
            if 'key' in cp['api']:
                key = cp['api']['key']
        if 'database' in cp:
            if 'localdb' in cp['database']:
                db = cp['database']['localdb']
    if not key:
        logging.error('API key not found.')
        rdict['status'] = 500
        rdict['message'] = 'Internal Server Error'

    url = ''
    update = False
    if request.method == 'GET':
        url = request.args.get('url')
        update = request.args.get('update')
    if not url:
        rdict['status'] = 400
        rdict['message'] = "The parameter 'url' is missing"

    if not rdict['status']:
        sbl = SafeBrowsingList(key, db_path=db, platforms=platforms)
        logging.debug(sbl.storage.get_threat_lists())
        #if update:
        #    sbl.update_hash_prefix_cache()
        u = URL(url)
        #res['url'] = {
        res = {
            'query': u.url,
            'canonical': u.canonical,
            'permutations': [],
        }
        for i in u.url_permutations(u.canonical):
            p = {
                'pattern': i,
                'sha256': to_hex(u.digest(i))
            }
            #res['url']['permutations'].append(p)
            res['permutations'].append(p)
            
        url_hashes = u.hashes
        full_hashes = list(url_hashes)
        cues = [to_hex(fh[0:4]) for fh in full_hashes]
        #res['cues'] = cues
        res['results'] = []
        matched = sbl.storage.lookup_hash_prefix(cues)
        for m in matched:
            prefix = to_hex(m[1])
            for p in res['permutations']:
                if re.match(prefix, p['sha256']):
                    result = {
                        'pattern': p['pattern'],
                        #'prefix': to_hex(m[1]),
                        'prefix': prefix,
                        'matched': str(m[0]),
                    }
                    res['results'].append(result)
        #bl = sbl.lookup_url(url)
        #res['matched'] = bl
        logging.info(res)
        res = jsonify(res)

    if not res:
        if not rdict["status"]:
            rdict["status"] = 400
            rdict["message"] = "Invalid request."
        res = jsonify(rdict)
        res.status_code = rdict["status"]

    return res 

if __name__ == '__main__':
    app.run(debug=True)
