import os
import json
from flask import Flask, render_template, request, Response, send_file, send_from_directory, make_response
from database import Base, db_session, engine
from model import Trusty, Report, TrustyType
import datetime
import sys
import threading
app = Flask(__name__)

db_lock = threading.Lock()

DIR = os.path.dirname(os.path.realpath(__file__))

host = "0.0.0.0"
port = 21100

_COLLECTOR = ""
with open(f"{DIR}/js/trusty-types.js", "r") as f:
    _COLLECTOR = f.read()
with open(f"{DIR}/js/trusty-types.collector.js", "r") as f:
    _COLLECTOR += f.read()

_MONITOR = ""
with open(f"{DIR}/js/trusty-types.js", "r") as f:
    _MONITOR = f.read()
with open(f"{DIR}/js/trusty-types.monitor.js", "r") as f:
    _MONITOR += f.read()

def resp_options():
    response = make_response()
    response.headers.add("Access-Control-Allow-Origin", "*")
    response.headers.add('Access-Control-Allow-Headers', "*")
    response.headers.add('Access-Control-Allow-Methods', "*")
    return response

def resp_json(obj):
    resp = Response(json.dumps(obj))
    resp.headers['Content-Type'] = 'application/json'
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp


def resp_ok():
    resp = Response('{"status": "OK"}')
    resp.headers['Content-Type'] = 'application/json'
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp

def resp_exist():
    resp = Response('{"status": "Already exists"}')
    resp.headers['Content-Type'] = 'application/json'
    resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp

def get_ip():
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        ip = request.remote_addr
    return ip


@app.route('/js/<path:js>')
def serve_js(js):
    return send_from_directory('js', js)

@app.route('/collect', methods = ['POST', 'OPTIONS'])
def collect():
    if request.method == 'OPTIONS':
        return resp_options()

    trust_event = request.get_json()

    with db_lock:
        exist = db_session.query(Trusty).filter_by(tr_hash = trust_event['t_hash']).all()
        if len(exist):
            return resp_exist()

        else:
            t = Trusty(trust_event['t_type'],
                        trust_event['t_hash'], trust_event['t_content'],
                        trust_event['t_domain'], trust_event['t_sample'],
                        trust_event['t_loc'])
            db_session.add(t)
            db_session.commit()
            return resp_ok()

@app.route('/report', methods = ['POST', 'OPTIONS'])
def report():
    if request.method == 'OPTIONS':
        return resp_options()

    violation_event = request.get_json()

    with db_lock:
        exist = db_session.query(Report).filter_by(re_hash = violation_event['t_hash']).all()
        if len(exist):
            return resp_exist()

        else:
            t = Report(violation_event['t_type'],
                        datetime.datetime.now(), get_ip(),
                        violation_event['t_hash'], violation_event['t_content'],
                        violation_event['t_sample'], violation_event['t_domain'], violation_event['t_loc'])
            db_session.add(t)
            db_session.commit()
            return resp_ok()

@app.route('/view/reports')
def list_reports():
    return list_reports_page(1)


@app.route('/view/reports/<int:page>')
def list_reports_page(page):
    reports = db_session.query(Report).all()
    return render_template('reports.html', reports = reports,
                           page_start = 1,
                           page_end = 5,
                           cur_page = page
                            )

@app.route('/view/whitelists')
def list_whitelists():
    return list_whitelists_page(1)

@app.route('/view/whitelists/<int:page>')
def list_whitelists_page(page):
    trustys = db_session.query(Trusty).all()
    return render_template('whitelists.html', trustys = trustys,
                           page_start = 1,
                           page_end = 5,
                           cur_page = page
                            )

@app.route('/api/report/<int:re_id>', methods = ['OPTIONS', 'GET'])
def get_report(re_id):
    if request.method == 'OPTIONS':
        return resp_options()

    t = db_session.query(Report).filter_by(re_id = re_id).first()
    return resp_json({
        "re_id": t.re_id,
        "re_type": t.get_type(),
        "re_content": t.re_content,
        "re_datetime": t.re_datetime.strftime("%Y-%m-%d %H:%M:%S"),
        "re_ip": t.re_ip,
    })

@app.route('/api/trust/<int:re_id>', methods = ['OPTIONS', 'GET'])
def api_trust(re_id):
    if request.method == 'OPTIONS':
        return resp_options()

    t = db_session.query(Report).filter_by(re_id = re_id).first()
    ret = t.trust()
    if ret == "":
        ret = "Success"

    return resp_json({
        "message": ret
    })

@app.route('/api/whitelist/<int:tr_id>', methods = ['OPTIONS', 'GET'])
def api_whitelist(tr_id):
    if request.method == 'OPTIONS':
        return resp_options()

    t = db_session.query(Trusty).filter_by(tr_id = tr_id).first()
    return resp_json({
        "tr_id": t.tr_id,
        "tr_type": t.get_type(),
        "tr_content": t.tr_content
    })

@app.route('/api/delete/<int:tr_id>', methods = ['OPTIONS', 'GET'])
def api_delete(tr_id):
    if request.method == 'OPTIONS':
        return resp_options()

    t = db_session.query(Trusty).filter_by(tr_id = tr_id).first()
    ret = t.delete()
    if ret == "":
        ret = "Success"

    return resp_json({
        "message": ret
    })

def return_whitelist():
    ts = db_session.query(Trusty).all()
    res_dict = dict()

    for trusty in ts:
        res_dict[trusty.tr_hash] = 1

    resp = '''
    const _TT_WHITELISTS = ''' + json.dumps(res_dict) + '''
    Object.freeze(_TT_WHITELISTS);
    '''

    return resp

@app.route('/collector.js')
def return_collector():
    resp = Response('''
    (function () {{
    {}
    }})();
        '''.format(_COLLECTOR))
    resp.headers["Content-Type"] = "application/javascript"
    return resp

@app.route('/monitor.js')
def return_monitor():
    resp = Response('''
    (function () {{
    {}

    {}
    }})();
        '''.format(return_whitelist(), _MONITOR))
    resp.headers["Content-Type"] = "application/javascript"
    return resp

if len(sys.argv) < 2:
    app.run(host = host, port = port, threaded = True, debug = True)
elif sys.argv[1] == 'initdb':
    Base.metadata.create_all(bind = engine)
    print("Init database")
