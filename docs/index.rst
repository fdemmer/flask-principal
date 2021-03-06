
Flask Principal
~~~~~~~~~~~~~~~


Introduction
============

Flask-Principal provides a loose framework to tie in providers of two
types of service, often located in different parts of a web application:

    1. Authentication providers
    2. User information providers

For example, an authentication provider may be oauth, using Flask-OAuth and
the user information may be stored in a relational database. Looseness of
the framework is provided by using signals as the interface.

The major components are the :class:`~flask.ext.principal.Identity`, 
:class:`~flask.ext.principal.Permission` 
(and :class:`~flask.ext.principal.permits.Permit`) and the
:class:`~flask.ext.principal.ResourceContext`.

    1. The :class:`~flask.ext.principal.Identity` represents the user, and is
       stored/loaded from various locations (eg session) for each request. The
       Identity is the user's avatar to the system. It contains the access
       rights that the user has.
    
    2. A :class:`~flask.ext.principal.permits.Permit` is the smallest grain of
       access control, and represents a specific parameter for the situation.
       For example "has the admin role", "can edit blog posts".
    
       Permits are any tuple, or probably could be object you like, but a tuple
       fits perfectly. The predesigned Need types (for saving your typing) are
       either pairs of (method, value) where method is used to specify
       common things such as `"role"`, `"user"`, etc. And the value is the
       value. An example of such is `('role', 'admin')`. Which would be a
       Need for a admin role. Or Triples for use-cases such as "The permission
       to edit a particular instance of an object or row", which might be represented
       as the triple `('article', 'edit', 46)`, where 46 is the key/ID for that
       row/object.
       
       Essentially, how and what Permits are is very much down to the user, and is
       designed loosely so that any effect can be achieved by using custom
       instances as Permits.

       Whilst a Need is a permission to access a resource, an Identity should
       provide a set of Permits that it has access to.

    2. A :class:`~flask.ext.principal.Permission` is a set of requirements, any of which should be
       present for access to a resource.

    3. A :class:`~flask.ext.principal.Denial` is a set of requirements, any of which may be present to deny
       access to a resource.
       
    4. An :class:`~flask.ext.principal.ResourceContext` is the context of a certain identity against a certain
       Permission. It can be used as a context manager, or a decorator.


.. graphviz::


    digraph g {
        rankdir="LR" ;
        node [ colorscheme="pastel19" ];
        fixedsize = "true" ;
        i [label="Identity", shape="circle" style="filled" width="1.2", fillcolor="1"] ;
        p [label="Permission", shape="circle" style="filled" width="1.2" fillcolor="2"] ;
        n [label="<all>Permits|{<n1>RolePermit|<n2>FunctionPermit|<n3>...}", shape="Mrecord" style="filled" fillcolor="3"] ;
        c [label="ResourceContext", shape="box" style="filled,rounded" fillcolor="4"] ;
        i -> c ;
        p -> c ;
        n:all -> p ;
        n:all -> i ;

    }


Usage examples
==============


Protecting access to resources
------------------------------

For users of Flask-Principal (not authentication providers), access
restriction is easy to define as both a decorator and a context manager. A
simple quickstart example is presented with commenting::

    from flask import Flask, Response
    from flask.ext.principal import Principal, Permission, RolePermit

    app = Flask(__name__)

    # load the extension
    p = Principal(app)

    # Create a permission with a single Permit, in this case a RolePermit.
    admin_permission = Permission(RolePermit('admin'))

    # protect a view with a principal for that permit
    @app.route('/admin')
    @admin_permission.require()
    def do_admin_index():
        return Response('Only if you are an admin')

    # this time protect with a context manager
    @app.route('/articles')
    def do_articles():
        with admin_permission.require():
            return Response('Only if you are admin')

Authentication providers
------------------------

Authentication providers should use the `identity-changed` signal to indicate
that a request has been authenticated. For example::


    from flask import current_app
    from flask.ext.principal import Identity, identity_changed

    def login_view(req):
        username = req.form.get('username')
        # check the credentials
        identity_changed.send(current_app._get_current_object(),
                              identity=Identity(username))

User Information providers
--------------------------

User information providers should connect to the `identity-loaded` signal to
add any additional information to the Identity instance such as roles. For
example::

    from flask.ext.principal import indentity_loaded, RolePermit, UserPermit

    @identity_loaded.connect_via(app)
    def on_identity_loaded(sender, identity):
        # Get the user information from the db
        user = db.get(identity.name)
        # Update the roles that a user can provide
        for role in user.roles:
            identity.provides.add(RolePermit(role.name))


Object-level permissions
------------------------

A useful pattern is providing a set of permissions for individual domain
classes. For example, suppose you have a class::

    class BlogPost(object):

        def __init__(self, title, author):
            self.title = title
            self.author = author

You want to provide edit permissions if at least one of the following #
conditions is true:

- the current user is a moderator
- the current user is the author of the blog post

The edit permission is provided as a property of **BlogPost**::

        @property
        def edit_permission(self):
            return Permission(RolePermit('moderator'),
                              UserPermit(self.author.username))

The post can now be checked for edit permissions in your view::

    @app.route("/edit/<int:post_id>/")
    def edit_post(post_id):

        post = BlogPost.get(post_id)
        post.edit_permission.test(403)

In this case the view will raise a **403** HTTP error if the user is
neither the author nor a moderator.


API
===

Using the extension
----------------------

.. autoclass:: flask.ext.principal.Principal
    :members:


Main Types
----------

.. autoclass:: flask.ext.principal.Identity
    :members:

.. autoclass:: flask.ext.principal.AnonymousIdentity
    :members:

.. autoclass:: flask.ext.principal.ResourceContext
    :members: identity, can, __enter__

.. autoclass:: flask.ext.principal.Permission
    :members:
    
.. autoclass:: flask.ext.principal.Denial
    :members:


.. _permits:

Permits
-------

.. automodule:: flask.ext.principal.permits

There are a few ``namedtuple`` based permits ready to be used:

.. autoclass:: flask.ext.principal.permits.Permit

.. autoattribute:: flask.ext.principal.permits.UserPermit

.. autoattribute:: flask.ext.principal.permits.RolePermit

.. autoattribute:: flask.ext.principal.permits.TypePermit

.. autoclass:: flask.ext.principal.permits.RowPermit

It is also possible to use class based permits.

.. autoclass:: flask.ext.principal.permits.BasePermit

.. autoclass:: flask.ext.principal.permits.SimplePermit

.. autoclass:: flask.ext.principal.permits.AuthTypePermit

.. autoclass:: flask.ext.principal.permits.FunctionPermit


Signals
-------

.. autoattribute:: flask.ext.principal.identity_changed

.. autoattribute:: flask.ext.principal.identity_loaded


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

