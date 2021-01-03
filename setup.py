from setuptools import setup, find_packages

setup(
    name='msdsalgs',
    packages=find_packages(),
    install_requires=[
        'pycryptodome',
        'pyutils @ git+ssh://git@github.com/vphpersson/pyutils.git#egg=pyutils'
    ]
)
