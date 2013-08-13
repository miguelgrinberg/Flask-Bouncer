"""
Flask-Bouncer
---------------

User authentication for Flask
"""
from setuptools import setup


setup(
    name='Flask-Bouncer',
    version='0.1.0',
    url='http://github.com/miguelgrinberg/Flask-Bouncer/',
    license='MIT',
    author='Miguel Grinberg',
    author_email='miguelgrinberg50@gmail.com',
    description='User authentication for Flask',
    long_description=__doc__,
    packages=['flask_bouncer', 'flask_bouncer/bouncer'],
    zip_safe=False,
    data_files=[('', ['README.md', 'LICENSE'])],
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask',
        'Flask-Login',
        'Flask-WTF',
        'Flask-MarrowMailer',
        'rauth',
        'passlib',
        'itsdangerous',
        'marrow.util'
    ],
    test_suite='nose.collector',
    test_requires=[
        'nose',
        'beautifulsoup4'
    ],
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
