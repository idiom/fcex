from setuptools import setup

setup(
    name='fcex',
    version='0.0.2',
    url='https://github.com/idiom/fcex',
    author='Sean Wilson',
    author_email='sean@idiom.ca',
    description='Python Library and commandline tool to work with FortiClient quarantine files',
    license='Apache License (V2)',
    classifiers=['Development Status :: 5 - Production/Stable',
                 'Intended Audience :: Developers',
                 'Intended Audience :: Science/Research',
                 'Natural Language :: English',
                 'Operating System :: OS Independent',
                 'Programming Language :: Python'],
    py_modules=['fcex'],
    entry_points={'console_scripts': ['fcex=fcex:main']}
)
