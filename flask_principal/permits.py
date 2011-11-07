import hashlib

"""
Permits are what was previously called "needs". An identity may carry a number
of permits and a ressource may require certain permits to allow access.

For most simple tasks tuples are perfect as Permits.

Other applications may need more than that or you might just be more 
comfortable working with class instances. The important part is, that permits 
must be hashable and comparable. They must at least implement the __hash__ 
and __eq__ functions.
"""

class BasePermit(object):
    """
    Use as base class for Permits, that are more complex than tuples. 
    To implement your own Permits overload the constructor, do what you need 
    to and in the end call super with arguments, that make the Permit unique 
    and comparable.
    """
    def __init__(self, *args, **kwargs):
        #: A clear text representation of what was used to create the hash.
        self.ident = list(args)+[k+"="+v for k, v in kwargs.items()]
        #: A md5 hash unique for this permit.
        self.hash = hashlib.md5("".join(self.ident)).hexdigest()

    def __hash__(self):
        return long(self.hash, 16)

    def __eq__(self, other):
        return self.hash == other.hash

class AuthTypeNeed(BasePermit):
    """
    A permit defining the type of authentication used. (eg. http-basic)
    This permit is automatically added by the default authentication loaders.
    If you implement your own authentication loader, be sure to do so too.
    """
    def __init__(self, auth_type):
        #: A short text description of the authentication type used or required.
        self.auth_type = auth_type
        super(AuthTypeNeed, self).__init__(permit_cls=self.__class__.__name__, 
            auth_type=auth_type)


