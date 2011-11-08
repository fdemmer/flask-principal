import hashlib
from functools import partial
from collections import namedtuple

"""
Permits are what was previously called "needs". An identity may carry a number
of permits and a ressource may require certain permits to allow access.

For most simple tasks tuples are perfect as Permits.

Other applications may need more than that or you might just be more 
comfortable working with class instances. The important part is, that permits 
must be hashable and comparable. They must at least implement the __hash__ 
and __eq__ functions.
"""

Permit = namedtuple('Permit', ['method', 'value'])
"""A required permit.

This is just a named tuple, and practically any tuple will do.

The ``method`` attribute can be used to look up element 0, and the ``value``
attribute can be used to look up element 1.
"""

UserPermit = partial(Permit, 'name')
UserPermit.__doc__ = """A permit with the method preset to `"name"`."""

RolePermit = partial(Permit, 'role')
RolePermit.__doc__ = """A permit with the method preset to `"role"`."""

TypePermit = partial(Permit, 'type')
TypePermit.__doc__ = """A permit with the method preset to `"type"`."""

ActionPermit = partial(Permit, 'action')
ActionPermit.__doc__ = """A permit with the method preset to `"action"`."""

RowPermit = namedtuple('RowPermit', ['method', 'value', 'type'])
"""A required item need

An item permit is just a named tuple. In addition to the fields of the other 
permits, there is a type, for example this could be specified as::

    RowPermit('update', 27, 'posts')
    ('update', 27, 'posts') # or like this

And that might describe the permission to update a particular blog post. In
reality, the developer is free to choose whatever convention the permissions
are.
"""

class BasePermit(object):
    """
    Use as base class for Permits, that are more complex than tuples. 
    To implement your own Permits overload the constructor, do what you need 
    to and finally call set_ident with arguments, that make the Permit unique 
    and comparable.
    """
    def __init__(self, **kwargs):
        self._kwargs = kwargs

    @property
    def ident(self):
        """A clear text representation of what is used to create the hash."""
        return ["{}='{}'".format(k, v) for k, v in self._kwargs.items()]

    @property
    def hash(self):
        """A md5 hash unique for this permit based on the ident."""
        return hashlib.md5("".join(self.ident)).hexdigest()

    def __repr__(self):
        return "<%s(%s)>" % \
            (self.__class__.__name__, ", ".join(self.ident))

    def __hash__(self):
        return long(self.hash, 16)

    def __eq__(self, other):
        return hash(self) == hash(other)

class SimplePermit(BasePermit):
    """
    Use SimplePermit to set any number of keywords arguments. The hash for 
    comparison will be generated on a dictionary generated from those 
    key/value pairs. Only keyword arguments are allowed.

    If you use "key" and "value" arguments, a SimplePermit is also comparable
    to a FunctionPermit. That way you can for example define the permits of
    an Identity using SimplePermit::

        # create identity for user with uid 1000
        identity = Identity(1000)
        # identity is owner of a eg. blog post with id 1234
        identity.add_permit(SimplePermit(key='owner', value='1234'))
        # identity is friend of user with id 5678
        identity.add_permit(SimplePermit(key='friend', value='5678'))

    and then a FunctionPermit is used to check the access within the
    request context of a view function. The function is evaluated
    to determine the value of "value" when Permission.allows() 
    is called (which happens when using Permission.required())::

        owner = Permission(FunctionPermit(key='owner', 
            func=lambda: request.view_args.get('post_id')))
        # only the owner is allowed to edit
        with owner.required():
            # edit post
            pass

    This also works as decorator::

        friend = Permission(FunctionPermit(key='friend', 
            func=lambda: request.view_args.get('user_id')))
        # only friends allowed to access
        @friend.required(403)
        def view_private_stuff(user_id):
            # return darkest secrets
            pass
    """
    pass

class AuthTypePermit(BasePermit):
    """
    A permit defining the type of authentication used. (eg. http-basic)
    This permit is automatically added by the default authentication loaders.
    If you implement your own authentication loader, be sure to do so too.
    """
    def __init__(self, auth_type):
        BasePermit.__init__(self, auth_type=auth_type)
        #: A short text description of the authentication type used or required.
        self.auth_type = auth_type

    def __repr__(self):
        return "<%s(auth_type='%s')>" % \
            (self.__class__.__name__, self.auth_type)

class FunctionPermit(BasePermit):
    """
    As described in SimplePermit, a FunctionPermit can be used to determine 
    a "value" keyword argument using a function within a request context, 
    instead of a fixed identifier.
    
    The function is evaluated as late as possible. Everytime the permit's
    hash is determined to be exact. This happens for example in 
    Permission.allows(), but also in a number of other Permission functions,
    that perform operations on the "allow" and "deny" sets.
    """
    def __init__(self, key, func):
        BasePermit.__init__(self, key=key)
        self.func = func
        if not callable(func):
            self._kwargs['value'] = func

    def __hash__(self):
        if callable(self.func):
            self._kwargs['value'] = self.func()
        return BasePermit.__hash__(self)


