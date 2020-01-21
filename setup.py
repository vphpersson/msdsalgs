from setuptools import setup, find_packages

setup(
    name='msdsalgs',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'pycryptodome',
        'ndr @ https://github.com/vphpersson/ndr/tarball/master'
    ]
)
