from flask import Flask, request, Response, jsonify, render_template, flash, redirect, g, url_for, session
app = Flask(__name__)
GKEY = app.secret_key = 'AIzaSyAsBJB7EatrohvAQArfqfCPSrP6s91reyY'
#app.debug = True

from werkzeug.exceptions import Unauthorized
class RequireID(Unauthorized):
    def get_description(self, env):
        vhost = env.get('SERVER_NAME') or env.get('HTTP_HOST') or ''
        return (
            '<a href="https://' + vhost + ':444/">MIT Certificate</a>'
            ' (<a href="https://ca.mit.edu/">help</a>)'
            ' or <a href="/login?provider=Gmail">Google Account</a>'
            ' required'
        )

import json, os, time

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
            line = line.strip()
            if line:
                r += [line.split('\t')]
    except IOError: pass
    return sorted(r, reverse=True)

def user_revoke(user, key):
    f = 'data/user/'+user+'/keys'
    r = user_keys(user)
    r = filter(lambda k: k[1] != key, r)
    s = ''
    for k in r:
        s += '\t'.join(k)+'\n'
    file(f,'w').write(s)

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
    t = key[0].strip() or 0
    return time.strftime('%c', time.gmtime(int(t)))

@app.route('/<u>')
@app.route('/user/<u>')
def user(u):
    for mtype, q in request.accept_mimetypes:
        if '/turtle' in mtype or '/n3' in mtype:
            return userTurtle(u)
        elif '/html' in mtype:
            return userHTML(u)

def userTurtle(u):
    r = '@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n@prefix cert: <http://www.w3.org/ns/auth/cert#> .\n'
    also = user_seeAlso(u)
    keys = user_keys(u)
    if also or keys:
        r += '<#> '
        if also:
            r += 'rdfs:seeAlso <' + also + '> '
            if keys:
                r += '; '
        n3 = []
        for ts, mod, ip, ua in keys:
            n3.append('''[ a cert:RSAPublicKey ; cert:exponent "65537" ; cert:modulus "''' + mod + '" ]')
        if keys:
            r += 'cert:key\n' + ',\n'.join(n3)
        r += ' .'
    return Response(r, mimetype='text/turtle')

def userHTML(u):
    return '''
<!doctype html><html id="docHTML"><head>
<link type="text/css" rel="stylesheet" href="https://w3.scripts.mit.edu/tabulator/tabbedtab.css" />
<script type="text/javascript" src="https://ajax.googleapis.com/ajax/libs/jquery/1.7.1/jquery.min.js"></script>
<script type="text/javascript" src="https://w3.scripts.mit.edu/tabulator/js/mashup/mashlib.js"></script>
<script type="text/javascript">

/* http://api.jquery.com/extending-ajax/#Prefilters */
jQuery.ajaxPrefilter(function(options) {
    if (options.crossDomain) {
        options.url = "https://w3.scripts.mit.edu/proxy?uri=" + encodeURIComponent(options.url);
    }
});

jQuery(document).ready(function() {
    var uri = window.location.href;
    window.document.title = uri;
    var kb = tabulator.kb;
    var subject = kb.sym(uri);
    tabulator.outline.GotoSubject(subject, true, undefined, true, undefined);
});
</script>
</head>
<body>
<div class="TabulatorOutline" id="DummyUUID">
    <table id="outline"></table>
</div>
</body>
</html>
'''

@app.before_request
def before_request():
    DN = {}
    for elt in request.environ.get('SSL_CLIENT_S_DN','').split('/'):
        lst = elt.split('=',1)
        if len(lst) > 1:
            DN[lst[0]] = lst[1]
    g.DN = DN

    g.hasLogout = False
    user = {}
    if 'CN' in DN and 'emailAddress' in DN:
        user = {'name': DN['CN'], 'mbox': DN['emailAddress']}
    if 'user' in session and session['user'] and 'mbox' in session['user'] and session['user']['mbox']:
        g.hasLogout = True
        user = session['user']
    g.user = user

    if not g.user:
        path = request.path.split('/') or ('', '')
        if path[1] in ('',) and not '@' in path[1]:
            raise RequireID()

import pki

@app.route('/', methods=['GET', 'POST'])
def index():
    hello = g.user['name']
    uid = g.user['mbox']

    uid = uid.lower()
    if uid[-8:] == '@mit.edu':
        uid = uid[:-8]

    vhost = request.host
    if ':' in vhost:
        vhost = vhost.split(':',1)[0]
    if request.environ.get('SSL_SERVER_I_DN_OU') in ('InCommon',):
        scheme = 'https:'
    else:
        scheme = 'http:'
    webid = scheme + '//' + vhost + '/'+uid+'#'

    submit = request.form.get('submit')
    if submit == 'revoke':
        user_revoke(uid, key=request.form.get('key'))

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

import httplib2
http = httplib2.Http()

def gverify():
    q = {
        'postBody': request.data,
        'requestUri': request.url,
        'userIp': request.remote_addr,
    }
    r = http.request('https://www.googleapis.com/identitytoolkit/v1/relyingparty/verifyAssertion?key=' + GKEY,
            method='POST', headers={'Content-Type': 'application/json'}, body=json.dumps(q))
    if int(r[0]['status']) == 200:
        return json.loads(r[1])

@app.route('/login')
def login():
    provider = request.values.get('provider')
    if provider:
        q = {
            'continueUrl': url_for('login', _external=True).replace('http:','https:'),
            'identifier': provider.lower()+'.com',
            'uiMode': 'redirect',
            'userIp': request.remote_addr,
        }
        r = http.request('https://www.googleapis.com/identitytoolkit/v1/relyingparty/createAuthUrl?key=' + GKEY,
                method='POST', headers={'Content-Type': 'application/json'}, body=json.dumps(q))
        j = json.loads(r[1])
        if int(r[0]['status']) == 200:
            if 'authUri' in j:
                return redirect(j['authUri'], 303)
        return jsonify(j)
    v = gverify() or {}
    if not 'verifiedEmail' in v:
        return jsonify(v)
    session['user'] = {
        'mbox': v['verifiedEmail'],
        'name': v.get('displayName') or (v.get('firstName','') + v.get('lastName','')) or v.get('name',''),
    }
    return redirect('/')

@app.route('/logout')
def logout():
    del session['user']
    return redirect('/')
