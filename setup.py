#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

requirements = [
    'sanic==0.8.3',
    'PyJWT==1.6.4',
    'jwcrypto==0.6.0',
    'aioboto3==5.0.0',
    'aiohttp==3.4.4',
    'aioredis==1.2.0'
]

setup_requirements = [
    'setuptools_scm>=3.1.0'
]

# test_requirements = [
#     'pytest',
#     'Sphinx',
#     'sphinx-autodoc-typehints',
#     'pytest-asyncio',
#     'pytest-aiohttp',
#     'requests',
#     'coverage'
# ]

setup(
    name='sanic_openid_connect_provider',

    use_scm_version={
        'tag_regex': r'^(?P<prefix>v)?(?P<version>[^\+]+)$',
        'write_to': 'sanic_openid_connect_provider/version.py'
    },
    description="OpenID Provider framework for sanic",
    long_description=readme,
    author="Terry Cain",
    author_email='terry@terrys-home.co.uk',
    url='https://github.com/terrycain/sanic-openid-provider',
    download_url='https://pypi.python.org/pypi/sanic-openid-provider',
    packages=find_packages(include=['sanic_openid_connect_provider']),
    include_package_data=True,
    install_requires=requirements,
    license="MIT",
    zip_safe=False,
    keywords='sanic openid provider',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.6',
    ],
    test_suite='tests',
    tests_require=[],
    setup_requires=setup_requirements,
)
