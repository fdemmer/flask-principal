class Loader(object):
    """
    Base class for identity loaders. Used directly always returns an 
    AnonymousIdentity instance.

    Create subclasses and override the __call__ method to implement how
    the client's identity is determined from the incoming HTTP request.
    The method shall return an Identity instance or None.

    However the Identity instance is usually created by the create_identity 
    method passed to the loader during initialization.
    """
    def __init__(self, create_identity=None):
        if create_identity is not None:
            self.create_identity = create_identity

    def __call__(self):
        return self.create_identity()

    def create_identity(self, *args, **kwargs):
        return AnonymousIdentity()

class HttpBasicLoader(Loader):
    """
    Identity loader for HTTP Basic authentication.

    The create_identity function is called with the credentials found in the
    HTTP Authorization header (username and password) and should return
    an Identity instance if the credentials are meaningful.

    The identity `auth_type` will be set to `"http-basic"` if not already set.

    For example::

        app = Flask(__name__)
        principal = Principal(app)

        def create_identity(username, password):
            user = model.User.query.filter(model.User.username == username)
            if user and user.validate_password(password):
                return Identity(user.id, user)
        principal.identity_loader(HttpBasicLoader(create_identity))
    """
    def __call__(self):
        auth = request.authorization
        if auth and auth['username'] and auth['password']:
            identity = self.create_identity(auth['username'], auth['password'])
            if identity and not identity.auth_type:
                identity.auth_type = "http-basic"
            return identity
