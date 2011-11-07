
from py.test import raises

from flask import Flask, Response, g

from flask.ext.principal import Principal, Permission, Denial, RoleNeed, \
    PermissionDenied, identity_changed, Identity, identity_loaded


def _on_principal_init(sender, identity):
    if identity.uid == 'ali':
        identity.provides(RoleNeed('admin'))

class ReraiseException(Exception):
    """For checking reraising"""
    
admin_permission = Permission(RoleNeed('admin'))
anon_permission = Permission()

admin_or_editor = Permission(RoleNeed('admin'), RoleNeed('editor'))

editor_permission = Permission(RoleNeed('editor'))

admin_denied = Denial(RoleNeed('admin'))

identity_users = {
	'ali': object(),
	'james': object(),
}

def mkapp():
    app = Flask(__name__)
    app.secret_key = 'notverysecret'
    app.debug = True

    p = Principal(app)

    @p.session_loader
    def user_by_uid(uid):
        if uid in identity_users:
            return Identity(uid, user=identity_users[uid])

    @p.http_basic_loader
    @p.form_loader(['/login'])
    def user_by_credential(login, password):
        if login in identity_users and login == password:
            return Identity(login, user=identity_users[login])

    identity_loaded.connect(_on_principal_init)

    @app.route('/')
    def index():
        with admin_permission.required():
            pass
        return Response('hello')

    @app.route('/a')
    @admin_permission.required()
    def a():
        return Response('hello')

    @app.route('/b')
    @anon_permission.required()
    def b():
        return Response('hello')

    @app.route('/c')
    def c():
        with anon_permission.required():
            raise ReraiseException

    @app.route('/d')
    @anon_permission.required()
    def d():
        raise ReraiseException

    @app.route('/e')
    def e():
        i = mkadmin()
        identity_changed.send(app, identity=i)
        with admin_permission.required():
            return Response('hello')

    @app.route('/f')
    def f():
        i = mkadmin()
        identity_changed.send(app, identity=i)
        with admin_or_editor.required():
            return Response('hello')

    @app.route('/g')
    @admin_permission.required()
    @editor_permission.required()
    def g_():
        return Response('hello')

    @app.route('/h')
    def h():
        i = Identity('james', user=identity_users['james'])
        identity_changed.send(app, identity=i)
        with admin_permission.required():
            with editor_permission.required():
                pass
    
    @app.route('/j')
    def j():
        i = Identity('james', user=identity_users['james'])
        identity_changed.send(app, identity=i)
        with admin_permission.required(403):
            with editor_permission.required(403):
                pass
    
    @app.route('/k')
    @admin_permission.required(403)
    def k():
        return Response('hello')

    @app.route('/l')
    def l():
        s = []
        if not admin_or_editor:
            s.append("not admin")

        i = Identity('ali', user=identity_users['ali'])
        identity_changed.send(app, identity=i)
        if admin_or_editor:
            s.append("now admin")  
        return Response('\n'.join(s))

    @app.route("/m")
    def m():
        with admin_denied.required():
           pass 
            
        return Response("OK")

    @app.route("/n")
    def n():
        i = mkadmin()
        identity_changed.send(app, identity=i)
        with admin_denied.required():
            pass

        return Response("OK")

    @app.route("/o")
    def o():
        admin_or_editor.test()
        return Response("OK")

    @app.route("/p")
    def p_():
        admin_or_editor.test(404)
        return Response("OK")

    @app.route("/login", methods=['GET', 'POST'])
    def login():
        return Response(g.identity.uid)

    @app.route("/logout")
    def logout():
        p.set_identity()
        return Response("OK")

    return app

def mkadmin():
    i = Identity('ali', user=identity_users['ali'])
    return i

def test_identity_creation():

    i = Identity(1)
    i.provides(RoleNeed('user'))
    
    assert i.provides == set([RoleNeed('user')])
    
    i.provides(RoleNeed('admin'), RoleNeed('operator'))
    
    assert i.provides == set([RoleNeed('user'), RoleNeed('admin'), 
        RoleNeed('operator')])

def test_identity_allowed():

    p1 = Permission(RoleNeed('boss'), RoleNeed('lackey'))
    p2 = Permission(RoleNeed('lackey'))
    
    i = Identity(1)
    i.provides(RoleNeed('boss'))
    
    assert p1.allows(i) == True
    assert p2.allows(i) == False

def test_deny_with():
    client = mkapp().test_client()
    raises(PermissionDenied, client.open, '/')

def test_deny_view():
    client = mkapp().test_client()
    raises(PermissionDenied, client.open, '/a')

def test_allow_view():
    client = mkapp().test_client()
    assert client.open('/b').data == 'hello'

def test_reraise():
    client = mkapp().test_client()
    raises(ReraiseException, client.open, '/c')

def test_error_view():
    client = mkapp().test_client()
    raises(ReraiseException, client.open, '/d')

def test_permission_union():
    p1 = Permission(('a', 'b'))
    p2 = Permission(('a', 'c'))
    p3 = p1.union(p2)
    assert p1.issubset(p3)
    assert p2.issubset(p3)

def test_permission_difference():
    p1 = Permission(('a', 'b'), ('a', 'c'))
    p2 = Permission(('a', 'c'), ('d', 'e'))
    p3 = p1.difference(p2)
    assert p3.needs == set([('a', 'b')])
    p4 = p2.difference(p1)
    assert p4.needs == set([('d', 'e')])


def test_permission_union_denial():
    p1 = Permission(('a', 'b'))
    p2 = Denial(('a', 'c'))
    p3 = p1.union(p2)
    assert p1.issubset(p3)
    assert p2.issubset(p3)

def test_permission_difference_denial():
    p1 = Denial(('a', 'b'), ('a', 'c'))
    p2 = Denial(('a', 'c'), ('d', 'e'))
    p3 = p1.difference(p2)
    assert p3.excludes == set([('a', 'b')])
    p4 = p2.difference(p1)
    assert p4.excludes == set([('d', 'e')])

def test_reverse_permission():

    p = Permission(('a', 'b'))
    d = p.reverse()
    print d.excludes
    assert ('a', 'b') in d.excludes

def test_identity_changed():
    client = mkapp().test_client()
    assert client.open('/e').data == 'hello'

def test_identity_load():
    client = mkapp().test_client()
    assert client.open('/e').data == 'hello'
    assert client.open('/a').data == 'hello'

def test_or_permissions():
    client = mkapp().test_client()
    assert client.open('/e').data == 'hello'
    assert client.open('/f').data == 'hello'

def test_and_permissions_view_denied():
    client = mkapp().test_client()
    raises(PermissionDenied, client.open, '/g')

def test_and_permissions_view():
    client = mkapp().test_client()
    raises(PermissionDenied, client.open, '/g')

def test_and_permissions_view_with_http_exc():
    client = mkapp().test_client()
    response = client.open("/j")
    assert response.status_code == 403

def test_and_permissions_view_with_http_exc_decorated():
    client = mkapp().test_client()
    response = client.open("/k")
    assert response.status_code == 403

#
# this test fails, because the permission only passed on with an exception,
# and not with an abort() any more. the code removed from principal from 
# __ender__ is: abort(self.abort_with, self.permission)
#
#def test_and_permissions_view_with_custom_errhandler():
#    app = mkapp()
#
#    @app.errorhandler(403)
#    def handle_permission_denied(error):
#        assert error.description == admin_permission
#        return Response("OK")
#
#    client = app.test_client()
#    response = client.open("/k")
#    assert response.status_code == 200
#

def test_permission_and():

    p1 = Permission(RoleNeed('boss'))
    p2 = Permission(RoleNeed('lackey'))

    p3 = p1 & p2
    p4 = p1.union(p2)

    assert p3.needs == p4.needs

def test_permission_or():

    p1 = Permission(RoleNeed('boss'), RoleNeed('lackey'))
    p2 = Permission(RoleNeed('lackey'), RoleNeed('underling'))

    p3 = p1 | p2
    p4 = p1.difference(p2)

    assert p3.needs == p4.needs

def test_contains():

    p1 = Permission(RoleNeed('boss'), RoleNeed('lackey'))
    p2 = Permission(RoleNeed('lackey'))

    assert p2.issubset(p1)
    assert p2 in p1

def test_permission_bool():

    client = mkapp().test_client()
    response = client.open('/l')
    assert response.status_code == 200
    assert 'not admin' in response.data
    assert 'now admin' in response.data

def test_denied_passes():

    client = mkapp().test_client()
    response = client.open("/m")
    assert response.status_code == 200

def test_denied_fails():

    client = mkapp().test_client()
    raises(PermissionDenied, client.open, '/n')

def test_permission_test():
    
    client = mkapp().test_client()
    raises(PermissionDenied, client.open, '/o')
    
def test_permission_test_with_http_exc():
    
    client = mkapp().test_client()
    response = client.open("/p")
    assert response.status_code == 404

def test_identity_user():
    client = mkapp().test_client()
    with client:
        response = client.open("/e")
        assert response.status_code == 200
        assert g.identity is not None
        assert g.user is identity_users['ali']

    with client:
        response = client.open("/a")
        assert response.status_code == 200
        assert g.identity is not None
        assert g.user is identity_users['ali']

def test_set_identity_none():
    app = mkapp()
    client = app.test_client()
    with client:
        response = client.open("/e")
        assert response.status_code == 200
        assert g.identity is not None
        assert g.user is identity_users['ali']

    client.open("/logout")
    raises(PermissionDenied, client.open, '/a')

def test_http_basic_loader_ok():
    client = mkapp().test_client()
    with client:
        response = client.open("/a", headers={'Authorization': ('Basic %s' % 'ali:ali'.encode('base64').strip())})
        assert response.status_code == 200
        assert g.identity is not None
        assert g.user is identity_users['ali']

def test_http_basic_loader_wrong():
    client = mkapp().test_client()
    raises(PermissionDenied, client.open, '/a', headers={'Authorization': ('Basic %s' % 'ali:foo'.encode('base64').strip())})

def test_form_loader():
    client = mkapp().test_client()
    with client:
        response = client.post("/login", data={'login': 'ali', 'password': 'ali'})
        assert response.status_code == 200
        assert g.identity is not None
        assert g.user is identity_users['ali']
        assert 'ali' in response.data

def test_form_loader_get_or_wrong():
    client = mkapp().test_client()
    raises(PermissionDenied, client.open, '/a', headers={'Authorization': ('Basic %s' % 'ali:foo'.encode('base64').strip())})
    with client:
        response = client.open("/login", data={'login': 'ali', 'password': 'ali'})
        assert response.status_code == 200
        assert g.identity.uid == 'anonymous'
        assert g.user is None

        response = client.post("/login", data={'login': 'ali', 'password': 'foo'})
        assert response.status_code == 200
        assert g.identity.uid == 'anonymous'
        assert g.user is None
