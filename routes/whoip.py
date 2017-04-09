from flask import Flask, request, jsonify, make_response, redirect
app = Flask(__name__)
from . import routes

from celery import Celery, group, result as cresult

app.config['CELERY_BROKER_URL'] = 'redis://localhost:6379/0'
app.config['CELERY_RESULT_BACKEND'] = 'redis://localhost:6379/0'

celery = Celery(app.name, broker=app.config['CELERY_BROKER_URL'])
celery.conf.update(app.config)

from werkzeug.contrib.cache import RedisCache
cache = RedisCache()

import os, sys, time, logging
logging.basicConfig(level=logging.DEBUG)

from ipwhois import IPWhois

fieldnames = [
    'query',
    'range',
    'cidr',
    'name',
    'county',
    'description',
]

@celery.task
def _whois_ip(ip):
    result = {}
    obj = None
    try:
        obj = IPWhois(ip)
        result = obj.lookup_whois(inc_raw=False)
        logging.debug(result["nets"])
    except Exception as e:
        logging.debug(e)
        result["error"] = str(e)
        result["query"] = str(ip)

    if result:
        result["reverse"] =  None
        try:
            rev = obj.net.get_host()
        except Exception as e:
            logging.debug(e)
            #result["reverse"] = str(e)

    return result


#@app.route('/whois', methods=['GET'])
@routes.route('/whois', methods=['GET'])
def whois():
    res = {}
    if request.method == 'GET':
        ip = request.args.get("ip")
        out = request.args.get("out")
        c = request.args.get("cache")
        if ip:
            #if cache.has(ip):
            #    logging.debug("cache exists -> " + ip)
            #    result = cache.get(ip)
            #else:
            if True:
                result = _whois_ip.delay(ip)
                result = result.get()
                cache.set(ip, result)
            if out == 'raw':
                res = result['jp']['raw']
            else:
                res = jsonify(result)
    return res

#@app.route('/whois/bulk/progress', methods=['GET'])
@routes.route('/whois/bulk/progress', methods=['GET'])
def bulkprogress():
    res = {}
    if request.method == 'GET':
        tid = request.args.get('id')
        gr = cresult.GroupResult()
        gt = gr.restore(tid, backend=celery.backend)
        for i in gt:
            if not i.state in ('SUCCESS', 'FAILURE'):
                res = {
                    "url":"/whois/bulk/progress?id="+tid
                }
                time.sleep(1)
                return redirect(res["url"])
            else:
                result = i.get()
                ip = result["query"]
                res[ip] = result
    return jsonify(res)

#@app.route('/whois/bulk', methods=['POST'])
@routes.route('/whois/bulk', methods=['POST'])
def bulkwhois():
    res = {}
    if request.method == 'POST':
        list = request.form['text']
        tasks = []
        for l in list.split("\r\n"):
            tasks.append(_whois_ip.s(l))
        gt = group(tasks)
        gr = gt()
        gr.save()
        logging.debug(gr)
        res = {
            "url":"/whois/bulk/progress?id="+gr.id
        }
        return redirect(res["url"])
    return jsonify(res)

#@app.route('/whois/form')
@routes.route('/whois/form')
def main_form():
    return """
Bulk Whois
<form action="/whois/bulk" id="textform" method="post">
<textarea style="width:400;" rows="10" name="text"></textarea><br>
<input type="submit" value="Submit">
</form>"""

if __name__ == '__main__':
    app.run(debug=True)
