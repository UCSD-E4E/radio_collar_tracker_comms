"""
RCT Comms
"""
from setuptools import setup, find_packages
from RCTComms import __version__

setup(
    name='RCTComms',
    version=__version__,
    description='Radio Collar Tracker Comms Library',
    author='UC San Diego - Engineers for Exploration',
    author_email='e4e@eng.ucsd.edu',
    packages=find_packages(),
    install_requires=[ 'pyserial' ],
    extras_require={
        'dev': [
            'pytest',
            'pylint',
            'pytest-timeout',
            'coverage',
            'wheel',
        ]
    },
)
