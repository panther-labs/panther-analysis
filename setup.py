from distutils.core import setup
setup(
    name='panther_cli',
    packages=['panther_cli'],
    version='0.1.5',
    license='gpl-3.0',
    description=
    'Panther command line interface for writing, testing, and packaging policies/rules.',
    author='Panther Labs Inc',
    author_email='hello@runpanther.io',
    url='https://github.com/panther-labs/panther-cli',
    # download_url = 'https://github.com/user/reponame/archive/v_01.tar.gz',
    keywords=['Security', 'CLI'],
    scripts=['bin/panther-cli'],
    install_requires=[
        'PyYAML',
        'schema',
    ],
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Topic :: Security',
        'License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)',
        'Programming Language :: Python :: 3.7',
    ],
)
