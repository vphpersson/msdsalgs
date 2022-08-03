from setuptools import setup, find_packages

setup(
    name='msdsalgs',
    version='0.11',
    packages=find_packages(),
    install_requires=[
        'pycryptodome',
        'pyutils @ git+https://github.com/vphpersson/pyutils.git#egg=pyutils',
        'string_utils_py @ git+https://github.com/vphpersson/string_utils_py.git#egg=string_utils_py',
        'ndr @ git+https://github.com/vphpersson/ndr.git#egg=ndr'
    ]
)
