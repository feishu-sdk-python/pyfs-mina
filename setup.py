# -*- coding: utf-8 -*-

from setuptools import setup


version = '1.0.5'


setup(
    name='pyfs-mina',
    version=version,
    keywords='Feishu Mini App',
    description='Feishu Module for Python for MiniApp.',
    long_description=open('README.rst').read(),

    url='https://github.com/feishu-sdk-python/pyfs-mina.git',

    author='Hackathon',
    author_email='kimi.huang@brightcells.com',

    packages=['pyfs_mina'],
    py_modules=[],
    install_requires=['pyfs-auth', 'pyfs-decrypt'],

    classifiers=[
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
