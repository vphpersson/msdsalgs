from setuptools import setup, find_packages

setup(
    name='msdsalgs',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'pycryptodome',
        'pyutils @ https://github.com/vphpersson/pyutils/tarball/master'
    ]
)
