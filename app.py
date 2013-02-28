#!/usr/bin/python
# app.py

from flask import Flask, request, Response, jsonify, render_template, abort, flash, redirect, g

app = Flask(__name__)
#app.debug = True
app.secret_key = 'mysecretkey'

import os, time

def user_add_key(user, key):
    f = 'data/user/'+user+'/keys'
    t = (str(int(time.time())), key.strip().lower(), request.remote_addr, request.user_agent.string)
    try: os.makedirs(os.path.dirname(f))
    except OSError: pass
    file(f,'a').write('\t'.join(t)+'\n')

def user_keys(user):
    r = []
    f = 'data/user/'+user+'/keys'
    try:
        for line in file(f):
            r += [line.split('\t')]
    except IOError: pass
    return sorted(r, reverse=True)

def user_seeAlso(user, new=None):
    f = 'data/user/'+user+'/seeAlso'
    r = ''
    if not new is None and len(new):
        try: os.makedirs(os.path.dirname(f))
        except OSError: pass
        file(f,'w').write(new.strip())
    try: r = file(f).read().strip()
    except: pass
    return r

@app.template_filter('key_when')
def key_when(key):
    return time.strftime('%c', time.gmtime(int(key[0])))

@app.route('/user/<u>')
def user(u):
    r = '@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n@prefix cert: <http://www.w3.org/ns/auth/cert#> .\n'
    also = user_seeAlso(u)
    keys = user_keys(u)
    if also or keys:
        r += '<#> '
        if also:
            r += 'rdfs:seeAlso <' + also + '> '
        r += keys and '; ' or '.'
        n3 = []
        for ts, mod, ip, ua in keys:
            n3.append('''[ a cert:RSAPublicKey ; cert:exponent "65537" ; cert:modulus "''' + mod + '" ]')
        if keys:
            r += 'cert:key\n' + ',\n'.join(n3) + ' .'
    return Response(r, mimetype='text/turtle')

@app.before_request
def before_request():
    DN = {}
    for elt in request.environ.get('SSL_CLIENT_S_DN','').split('/'):
        lst = elt.split('=',1)
        if len(lst) > 1:
            DN[lst[0]] = lst[1]
    if not DN:
        path = request.url.split('/')
        if len(path) < 4 or not path[3] in ('user',):
            abort(403, 'MIT certificate required (see https://ca.mit.edu/)')
    g.DN = DN

import pki

@app.route('/', methods=['GET', 'POST'])
def index():
    hello = g.DN.get('CN','')
    uid = g.DN.get('emailAddress','').split('@')[0]
    webid = 'http://webid.mit.edu/user/'+uid+'#'

    seeAlso1 = request.form.get('seeAlso')
    seeAlso = user_seeAlso(uid, seeAlso1)
    if seeAlso1 and seeAlso == seeAlso1:
        flash('Success updating seeAlso')

    x509cn = request.form.get('x509cn') or (hello+' (WebID)')
    x509days = int(request.form.get('x509days') or 365)
    spkac = request.form.get('spkac','').replace('\n','').replace('\r','')
    if spkac:
        x509 = pki.spkac_x509(spkac, x509cn, x509days, altName=webid)
        user_add_key(uid, pki.x509_mod(x509))
        flash('Success adding new key')
        return Response(pki.x509_asn1(x509), mimetype='application/x-x509-user-cert')

    keys = user_keys(uid)
    return render_template('index.html', **locals())

@app.route('/favicon.ico')
def favicon():
    return redirect('https://scripts.mit.edu/favicon.ico', 302)
