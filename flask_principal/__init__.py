# -*- coding: utf-8 -*-
"""
    flaskext.principal
    ~~~~~~~~~~~~~~~~~~

    Identity management for Flask.

    :copyright: (c) 2010 by Ali Afshar, Dan Jacob, Raphaël Slinckx.
    :copyright: (c) 2011 by Pedro Algarvio, Florian Demmer.
    :license: MIT, see LICENSE for more details.

"""

import sys
from functools import wraps
from collections import deque


from flask import g, session, current_app, abort, request
from flask.signals import Namespace

from permits import *


signals = Namespace()
"""Namespace for principal's signals.
"""


identity_changed = signals.signal('identity-changed', doc=
"""Signal sent when the identity for a request has been changed.

Actual name: ``identity-changed``

Authentication providers should send this signal when authentication has been
successfully performed. Principal connects to this signal and causes the
identity to be saved in the session.

For example::

    from flaskext.principal import Identity, identity_changed

    def login_view(req):
        uid = req.form.get('username')
        # check the credentials
        identity_changed.send(app, identity=Identity(uid))
""")


identity_loaded = signals.signal('identity-loaded', doc=
"""Signal sent when the identity has been initialised for a request.

Actual name: ``identity-loaded``

Identity information providers can connect to this signal to perform two
major activities (in addition to what the identity loader already may have done):

    1. Populate the identity object with the necessary authorization provisions.
    2. Load any additional user information.

For example::

    from flaskext.principal import identity_loaded, RolePermit, UserPermit

    @identity_loaded.connect
    def on_identity_loaded(sender, identity):
        # Get the user information from the db
        user = db.get(identity.name)
        # Update the roles that a user can provide
        for role in user.roles:
            identity.provides(RolePermit(role.name))
        # Save the user object in the Identity, so we only look it up once
        identity.user = user
""")


class PermissionDenied(RuntimeError):
    """
    Permission denied to the resource
    """
    pass

class Identity(object):
    """
    Represent the client's identity.

    :param uid: A unique identifier (the login name, an internal id, ...)
    :param user: The user object corresponding to that user identifier (made
                 available as `g.user`)
    :param auth_type: The authentication type used to confirm the user's
                      identity.

    The identity is used to represent the user's identity in the system. This
    object is created on login, or on the start of the request as loaded from
    the user's session.

    Once loaded it is sent using the `identity-loaded` signal, and should be
    populated with additional required information.

    Permits that are provided by this identity should be added using 
    add_permit() after loading.
    """
    def __init__(self, uid, **kwargs):
        
        class RoleSet(set):
            def __call__(self, *args):
                for arg in args:
                    self.add(arg)
        
        self.uid = uid
        self.args = kwargs
        self.user = kwargs.get('user', None)
        self.auth_type = kwargs.get('auth_type', None)
        
        self.provides = RoleSet()
        """
        Add one or more Permits, so that this Identity can provide them::
            
            identity = Identity('ali')
            identity.provides(RolePermit('guest'))
            identity.provides(('role', 'admin'), ('role', 'dba'))
            
        Is also used to access the provided Permit::
        
            permits.issubset(identity.provides)
            
        """

    def add_permit(self, permit):
        self.provides.add(permit)

    def can(self, permission):
        """
        Whether the identity has access to the permission.

        :param permission: The permission to test provision for.
        """
        return permission.allows(self)


class AnonymousIdentity(Identity):
    """
    The default Identity when no other is available. Uses "anonymous" as uid
    and all other fields using defaults from the Identity class.

    :attr uid: `"anon"`
    :attr user: `None`
    """
    def __init__(self):
        Identity.__init__(self, 'anonymous')


class ResourceContext(object):
    """
    The context for examining whether the Identity has Permission to whatever
    the ResourceContext is wrapped around.
    
    .. note:: The context is usually created by the Permission.required()
              method and can be used as a context manager (``with`` statement)
              or a decorator.
    
    The permission is checked for provision in the identity, and if available
    the flow is continued (context manager) or the function is executed
    (decorator), otherwise an appropriate exception is raised.
    """

    def __init__(self, permission, abort_with=None):
        """
        Create a ResourceContext with the given Permission.
        
        :attr permission:   The permission required to access the resource.
        :attr abort_with:   A HTTP error code to use with abort() in case
                            access is denied.
                            This defaults to None. In that case a
                            PermissionDenied exception is raised.
        """
        self.permission = permission
        self.abort_with = abort_with

    @property
    def identity(self):
        """
        The Identity in this context, as stored in the Flask global ``g``.
        """
        return g.identity

    def can(self):
        """
        Check if the Identity provides the Permission.
        """
        return self.identity.can(self.permission)

    def __call__(self, func):
        @wraps(func)
        def decorated(*args, **kwargs):
            self.__enter__()
            exc = (None, None, None)
            try:
                result = func(*args, **kwargs)
            except Exception:
                exc = sys.exc_info()
            self.__exit__(*exc)
            return result
        return decorated

    def __enter__(self):
        """
        The context guard returns the current Identity::
        
            protected_resource = ResourceContext(Permission(('role', 'admin')))
            with protected_resource() as ident:
                # ident is allowed to access resource
                pass
        """
        # check the permission and abort on error
        if not self.permission.allows(self.identity):
            if self.abort_with is not None:
                abort(self.abort_with)
            raise PermissionDenied(self.permission)

        # return current identity on success
        return self.identity

    def __exit__(self, *exc):
        """Context tear down."""
        if exc != (None, None, None):
            cls, val, tb = exc
            raise cls, val, tb
        # do not swallow any exceptions
        return False


class Permission(object):
    """
    A permission is a collection of permits, any of which must be allowed 
    or must not be denied to access a resource. Use Permission and Denial 
    to construct combinations.

    :param permits: The permits for this permission
    """
    def __init__(self, *permits):
        """
        A set of permits, any of which must be present in an identity to have
        access.
        """
        self.permits = list(permits)
        self.excludes = list()

    @property
    def allow(self):
        """A *set* of Permits, that are required to be allowed."""
        return set(self.permits)

    @property
    def deny(self):
        """
        A *set* of Permits, that are required to be denied.
        In other words, an Identity may not have those to gain access.
        """
        return set(self.excludes)

    def __nonzero__(self):
        """Equivalent to ``self.can()``.
        """
        return bool(self.can())

    def __and__(self, other):
        """Does the same thing as ``self.union(other)``
        """
        return self.union(other)
    
    def __or__(self, other):
        """Does the same thing as ``self.difference(other)``
        """
        return self.difference(other)

    def __contains__(self, other):
        """Does the same thing as ``other.issubset(self)``.
        """
        return other.issubset(self)

    def required(self, *args, **kwargs):
        """
        Create a ResourceContext from this Permission.

        See ResourceContext for valid arguments.
        """
        return ResourceContext(self, *args, **kwargs)

    def test(self, *args, **kwargs):
        """
        Checks if permission available and raises the relevant exception 
        if not (eg. PermissionDenied). This is useful if you just want to 
        check permission without wrapping everything in a with-required() 
        block.

        It still needs a request context though! The arguments are the 
        same as with required() (and the ResourceContext constructor).

        This is equivalent::

            permission.test()
            with permission.required():
                pass
        """
        with self.required(*args, **kwargs):
            pass
        
    def reverse(self):
        """
        Returns reverse of current state (permits->excludes, excludes->permits) 
        """
        p = Permission()
        p.permits = list(self.deny)
        p.excludes = list(self.allow)
        return p

    def union(self, other):
        """Create a new permission with the requirements of the union of this
        and other.

        You can also use the **&** operator. The following are equivalent::

            p = p1.union(p2)
            p = p1 & p2

        :param other: The other permission
        """
        p = Permission(*self.allow.union(other.allow))
        p.excludes = list(self.deny.union(other.deny))
        return p

    def difference(self, other):
        """Create a new permission consisting of requirements in this 
        permission and not in the other.

        You can also use the "|" operator. The following are equivalent::

            p = p1.difference(p2)
            p = p1 | p2
        """
        p = Permission(*self.allow.difference(other.allow))
        p.excludes = list(self.deny.difference(other.deny))
        return p

    def issubset(self, other):
        """Whether this permits are a subset of another

        You can also use the **in** operator. The following are equivalent::

            assert p1.issubset(p2)
            assert p1 in p2

        :param other: The other permission
        """
        return self.allow.issubset(other.allow) and \
            self.deny.issubset(other.deny)

    def allows(self, identity):
        """Whether the Identity can access this Permission.

        :param identity: The identity
        """
        if self.allow and not self.allow.intersection(identity.provides):
            return False

        if self.deny and self.deny.intersection(identity.provides):
            return False

        return True
       
    def can(self):
        """Whether the required context for this permission has access

        This creates an identity context and tests whether it can access this
        permission

        You can also check the permission directly. The following are 
        equivalent::

            assert permission.require().can()
            assert permission
        """
        return self.required().can()


class Denial(Permission):
    """
    Class for handling negative permissions. This is the same as a 
    **Permission**, but is initialized with a given set of excludes rather
    than permits.

    Excludes are the same as permits (and use the same classes) but the
    difference is that if an identity has a permit, they have
    permission, while if they have an exclude, they do not have
    the permission.

    You can combine a **Denial** and a **Permission** (or a **Denial** and 
    another **Denial**) in the same way as a **Permission** and another 
    **Permission**. For example::

        p = Permission(RolePermit('auth')) & Denial(UserPermit('me'))

    The resulting **Permission** *p* would pass if the identity provided the 
    **RolePermit** 'auth' but would fail if the identity also provided the 
    **UserPermit** 'me'.

    :param excludes: The excludes for this permission
    """

    def __init__(self, *permits):
        self.excludes = list(permits)
        self.permits = list()


class Principal(object):
    """The Principal extension
    
    ... provides Identity loaders (and saver)

    :param app: The flask application to extend
    :param skip_static: Skip triggering identity loaders and saver for the
                        current app's static path
    """
    def __init__(self, app=None, skip_static=False):
        self.identity_loaders = deque()
        self.identity_savers = deque()
        self.skip_static = skip_static
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.before_request(self._on_before_request)
        identity_changed.connect(self._on_identity_changed, app)

    def set_identity(self, identity=None):
        """Set the current identity. If identity is None, an anonymous identity is set

        :param identity: The identity to set
        """
        if identity is None:
            identity = AnonymousIdentity()

        if self.skip_static and \
            request.path.startswith(current_app.static_path):
            return

        self._set_thread_identity(identity)
        for saver in self.identity_savers:
            saver(identity)

    def identity_loader(self, func):
        """Decorator to define a function as an identity loader.

        An identity loader function is called before request to find any
        provided identities. The first found identity is used to load from.

        For example::

            app = Flask(__name__)

            principals = Principal(app)

            @principals.identity_loader
            def load_identity_from_weird_usecase():
                return Identity('ali')
        """
        self.identity_loaders.appendleft(func)
        return func

    def identity_saver(self, func):
        """Decorator to define a function as an identity saver.

        An identity loader saver is called when the identity is set to persist
        it for the next request.

        For example::

            app = Flask(__name__)

            principals = Principal(app)

            @principals.identity_saver
            def save_identity_to_weird_usecase(identity):
                my_special_cookie['identity'] = identity
        """
        self.identity_savers.appendleft(func)
        return func

    def session_loader(self, identity_by_uid_fn):
        """Decorator to enable session identity loading and saving.

        The decorated function is called with an user identifier and should return
        an identity if the user identifier is meaningful.

        If an identity is returned then it will be set as the current identity,
        otherwise Principal will continue looking for another identity.

        The identity `auth_type` will be set to `"session"` if not already set.

        This also enables the session identity saver which will store the
        user identifier in the session cookie or remove the user identifier
        if an anonymous identity is loaded.

        For example::

            app = Flask(__name__)

            principals = Principal(app)

            @principals.session_loader
            def get_identity_by_uid(uid):
                user = model.User.query.get(uid)
                if user:
                    return Identity(user.id, user)
        """
        def authenticate_session():
            uid = session.get('uid')
            if not uid:
                return
            identity = identity_by_uid_fn(uid)
            if identity:
                identity.add_permit(AuthTypePermit('session'))
            return identity

        def remember_session(identity):
            if not isinstance(identity, AnonymousIdentity):
                session['uid'] = identity.uid
            elif 'uid' in session:
                del session['uid']
            session.modified = True

        self.identity_loader(authenticate_session)
        self.identity_saver(remember_session)
        return identity_by_uid_fn

    def http_basic_loader(self, identity_by_credentials_fn):
        """
        Decorator to enable HTTP Basic identity loading.

        The decorated function is called with the credentials found in the
        HTTP Authorization header (username and password) and should return
        an identity if the credentials are meaningful.

        If an identity is returned then it will be set as the current identity,
        otherwise Principal will continue looking for another identity.

        The identity `auth_type` will be set to `"http-basic"` if not already set.

        For example::

            app = Flask(__name__)

            principals = Principal(app)

            @principals.http_basic_loader
            def get_identity_by_credentials(username, password):
                user = model.User.query.filter(model.User.username == username)
                if user and user.validate_password(password):
                    return Identity(user.id, user)
        """
        def authenticate_http_basic():
            a = request.authorization
            if a and a['username'] and a['password']:
                identity = identity_by_credentials_fn(a['username'], a['password'])
                if identity:
                    identity.add_permit(AuthTypePermit('http-basic'))
                return identity

        self.identity_loader(authenticate_http_basic)
        return identity_by_credentials_fn

    def form_loader(self, login_paths=[]):
        """Decorator to enable HTTP POST-style identity loading.

        The decorated function is called with the credentials posted at
        one of the login paths defined (login and password) and should return
        an identity if the credentials are meaningful.

        If an identity is returned then it will be set as the current identity,
        otherwise Principal will continue looking for another identity.

        The POST parameters are called `login` for the user login and `password`
        for the user password.

        The identity `auth_type` will be set to `"form"` if not already set.

        For example::

            app = Flask(__name__)

            principals = Principal(app)

            @principals.form_loader(['/login', '/special/logon'])
            def get_identity_by_credentials(username, password):
                user = model.User.query.filter(model.User.username == username)
                if user and user.validate_password(password):
                    return Identity(user.id, user)
        """
        def decorate(identity_by_credentials_fn):
            def authenticate_form():
                if request.path not in login_paths or request.method != 'POST':
                    return

                login, password = request.form.get('login', u''), request.form.get('password', u'')
                if not login:
                    return

                identity = identity_by_credentials_fn(login, password)
                if identity:
                    identity.add_permit(AuthTypePermit('form'))
                return identity

            self.identity_loader(authenticate_form)
            return identity_by_credentials_fn
        return decorate

    def _set_thread_identity(self, identity):
        g.identity = identity
        g.user = identity.user
        identity_loaded.send(current_app._get_current_object(),
                             identity=identity)

    def _on_identity_changed(self, app, identity):
        self.set_identity(identity)

    def _on_before_request(self):
        if self.skip_static and \
            request.path.startswith(current_app.static_path):
            return
        # loop through all registered loaders until...
        for loader in self.identity_loaders:
            identity = loader()
            # one successfully loads an identity and ...
            if identity is not None:
                # set it!
                self.set_identity(identity)
                return
        # otherwise set the fallback/anonymous identity
        self.set_identity()
