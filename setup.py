from setuptools import setup

setup(
    name='msdsalgs',
    version='0.9',
    url='https://github.com/vphpersson/msdsalgs',
    author='vph',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries',
        'Programming Language :: Python :: 3.7',
    ],
    packages=['msdsalgs'],
    py_modules=['ColoredOutput', 'Progressor'],
    python_requires='>=3.7'
)
