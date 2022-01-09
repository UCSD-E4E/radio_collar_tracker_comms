from setuptools import setup, find_packages
import RCTComms

setup(
    name='RCTComms',
    description='Radio Collar Tracker Comms Library',
    author='UC San Diego - Engineers for Exploration',
    author_email='e4e@eng.ucsd.edu',
    packages=find_packages(),
    install_requires=[
        'pytest'
    ],
)