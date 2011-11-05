"""
Flask-Principal
---------------

Identity management for Flask.

Links
`````

* `documentation <http://packages.python.org/Flask-Principal/>`_
* `development version
  <https://github.com/fdemmer/flask-principal>`_

"""
from setuptools import setup


setup(
    name='Flask-Principal',
    version='0.2.1',
    url='http://packages.python.org/Flask-Principal/',
    license='MIT',
    author='Ali Afshar',
    author_email='aafshar@gmail.com',
    description='Identity management for Flask',
    long_description=__doc__,
    packages=['flask_principal'],
    zip_safe=False,
    platforms='any',
    install_requires=[
        'Flask', 
        'blinker', 
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
