#!/usr/bin/python

from setuptools import setup, find_packages

name = 'liteauth'
version = '0.1'

setup(
    name=name,
    version=version,
    description='liteauth',
    license='Apache License (2.0)',
    author='LiteStack, Inc.',
    author_email='support@litestack.com',
    url='http://zerovm.org',
    packages=find_packages(exclude=['test', 'bin']),
    test_suite='nose.collector',
    classifiers=[],
    install_requires=[],
    scripts=[],
    entry_points={
        'paste.filter_factory': [
            'liteauth=liteauth.liteauth:filter_factory',
            'liteauth_token=liteauth.liteauth_token:filter_factory',
            'litequota=liteauth.litequota:filter_factory',
            'litebilling=liteauth.litebilling:filter_factory',
            'liteaccounting=liteauth.liteaccounting:filter_factory',
            'liteswauth=liteauth.swauth_manager:filter_factory',
            'oauthlogin=liteauth.oauth_login:filter_factory',
        ],
    },
)
