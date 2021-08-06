from setuptools import setup, find_packages

setup(
    name='msdsalgs',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'pycryptodome',
        'pyutils @ git+ssh://git@github.com/vphpersson/pyutils.git#egg=pyutils',
        'pyutils @ git+ssh://git@github.com/vphpersson/ndr.git#egg=ndr'
    ]
)
