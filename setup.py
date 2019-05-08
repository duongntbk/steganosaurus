from setuptools import setup

requires = [
    'cryptography>=2.3.1',
    'bitarray >= 0.8.3',
    'Pillow>=5.3.0',
    'bcrypt>=3.1.4'
]

test_requirements = [
    'pytest-mock',
    'pytest>=3.7.1'
]

with open('README.md', 'r') as fh:
    long_description = fh.read()

setup(
   name='steganosaurus',
   version='1.0.1',
   description='Hide data into image file',
   author='Nguyen Thai Duong',
   author_email='duongnt.bk@gmail.com',
   long_description=long_description,
   long_description_content_type='text/markdown',
   url='https://github.com/duongntbk/steganosaurus',
   packages=['steganosaurus'],  #same as name
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
   install_requires=requires,
   tests_require=test_requirements,
)