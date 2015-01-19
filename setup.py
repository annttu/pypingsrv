from codecs import open
from setuptools import setup, find_packages


long_description = "Pure Python ping server with event handlers"


setup(name='pypingsrv',
      version='0.1',
      description="Pure Python ping server",
      long_description=long_description,
      classifiers=[],
      keywords='ping',
      author='Antti Jaakkola',
      author_email='pypingsrv@annttu.fi',
      url='https://github.com/annttu/pypingsrv',
      license='MIT',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=True,
      install_requires=[],
      extras_require={
          'test': ['pytest']
      }
      )
