A XML Signature (XMLDSig) is a syntax to provide digital signatures of an XML file. These can be contained within that XML file itself (enveloped). 

In Python, the pyXMLSec library is a wrapper for the libxmlsec C-library. The wrapper is built closely to the low-level API and this means that the module has lots of calls the developer generally should not care about.

The xmldsig library is a convenience wrapper for the pyXMLSec library. It has been built initially to be used for the Dutch iDEAL payment processing system, but has been extended for use by other parties.

The library is inspired by the code examples of the pyXMLSec library and [the library made by Philippe Lagadec](http://www.decalage.info/python/pyxmldsig). However, his library lacks the ability to specify the key format, which is required to load certificates as keys with names and has been the main reason for the development of this module.


Installation
============
To use this library, you need to have installed two libraries:

* [python-libxml2](http://xmlsoft.org/python.html)
* [pyXMLSec](http://pyxmlsec.labs.libre-entreprise.org/)

The first requires you to install libxml2 and libxslt, the latter requires the libxmlsec library (we had to tell our OS to install libxml2-devel, libxslt-devel, xmlsec1-devel, xmlsec1-openssl-devel, and libtool-ltdl-devel).

Some notes to these packages:

* The python-libxml2 library does not provide a proper download link in PyPI and a direct download link is provided in requirements.txt. 
* The pyxmlsec library does not build properly on x64 systems, which is why pyxmlsec-next is included in requirements.txt. This is the pyxmlsec library, built from [the Github repository of pyxmlsec](https://github.com/dnet/pyxmlsec). Not using pyxmlsec-next would result in failing verification on these systems.

After you have successfully downloaded and installed the required libraries, you should be able to run `python setup.py install` without any problems.

You should run the tests by executing `python setup.py test` to verify installation went according to plan.


Basic usage
===========

Keys
----
Generally, you would want to generate a keypair to work and test with. You can create a keys and certificates using the OpenSSL application as follows:

```bash
openssl genrsa -aes128 -passout pass:foobar -out test.pem 2048                     # private key
openssl rsa -in test.pem -passin pass:foobar -pubout -out test.pub                 # public key
openssl req -x509 -new -key test.pem -passin pass:foobar -days 3650 -out test.cer  # self-signed x509 certificate
```

Note that there are onelines that do the same. Some example certificates are included in the package.


Signing
-------
Assuming you pass the XML as a string containing the XMLDsig template, you can sign a file as follows (this example is similar to [the first example of the pyXMLSec library](http://pyxmlsec.labs.libre-entreprise.org/index.php?section=examples&id=1)):

```python
>>> xml="""<?xml version="1.0" encoding="UTF-8"?>
... <Envelope xmlns="urn:envelope">
...   <Data>
...     Hello, World!
...   </Data>
...   <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
...     <SignedInfo>
...       <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
...       <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
...       <Reference URI="">
...         <Transforms>
...           <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
...         </Transforms>
...         <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
...         <DigestValue></DigestValue>
...       </Reference>
...     </SignedInfo>
...     <SignatureValue/>
...     <KeyInfo>
...     <KeyName/>
...     </KeyInfo>
...   </Signature>
... </Envelope>"""
>>> xmldsig.sign(xml, 'keyfile.key', 'password', 'name')
(...)
```

If you do not wish to provide a template yourself, you could let the module generate one for you:

```python
>>> xml = '<Envelope xmlns="urn:envelope"><Data>Hello, World!</Data></Envelope>'
>>> xmldsig.sign(xml, 'keyfile.key', 'password', 'name', 
...              canonicalization='exc-c14n', signing='rsa-sha256',
...              references={'sha256': ('enveloped-signature', )})
(...)
```

Verification
------------

There are simple methods to verify a signature:

```python
>>> xmldsig.verify(xml, 'keyfile.key', 'password', 'name')
True
>>> xmldsig.verify(xml, 'certfile.cer', None, 'name', key_format='cert-pem')
False
```

You can also use the XMLDSIG class to load multiple keys into memory:

```python
>>> verifier = xmldsig.XMLDSIG()
>>> verifier.load_key('keyfile.key', 'password', 'name')
>>> verifier.load_key('certfile.cer', None, 'name', key_format='cert-pem')
>>> verifier.verify(xml)
True
```

Similarly, you can sign using the class. The key to be used can be specified by providing the correct KeyName attribute, or by providing the key name in the XML file you supply to the signer. Otherwise, the first in-memory key is used.

Note that the full xmlsec library is not utilized and only limited signing and verification are possible. Encryption/decryption has not been implemented.


Changelog
=========
* **0.2.1, 2013-06-19** Fixed issue where the crypto app was not loaded and where xmldsig.sign() would not work properly
* **0.2, 2013-05-08** Added ability to generate templates
* **0.1, 2013-03-17** Initial version