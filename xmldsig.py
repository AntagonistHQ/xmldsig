import libxml2
import xmlsec

"""Convenience methods as a wrapper for the pyXMLSec library. Built initially
to be used by an iDeal library, a Dutch payment processing system using XML-DSIG
but usable by everyone requiring XML signatures.

This library is inspired by the code examples of the pyXMLSec library and the
library made by Philippe Lagadec (http://www.decalage.info/python/pyxmldsig).
However, this library lacks the ability to specify the key format, which is
required to load certificates as keys with names.

Requires the pyXMLSec library (http://pyxmlsec.labs.libre-entreprise.org/) and 
the libxml2 library to function. 

Note that all XML must be passed as strings containing the XML-DSig template.

Example for signing (similar example as 
http://pyxmlsec.labs.libre-entreprise.org/index.php?section=examples&id=1)

>>> xml=\"\"\"<?xml version="1.0" encoding="UTF-8"?>
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
... </Envelope>\"\"\"
>>> xmldsig.sign(xml, 'keyfile.key', 'password', 'name')
(...)

You can also not provide a template and provide the arguments to create one to
the module:

>>> xml = '<Envelope xmlns="urn:envelope"><Data>Hello, World!</Data></Envelope>'
>>> xmldsig.sign(xml, 'keyfile.key', 'password', 'name', 
...              canonicalization='exc-c14n', signing='rsa-sha256',
...              references={'sha256': ('enveloped-signature', )})
(...)
                      
Example for verification:

>>> xmldsig.verify(xml, 'keyfile.key', 'password', 'name')
True
>>> xmldsig.verify(xml, 'certfile.cer', None, 'name', key_format='cert-pem')
False

You can also use the XMLDSIG class to load multiple keys into memory:

>>> verifier = xmldsig.XMLDSIG()
>>> verifier.load_key('keyfile.key', 'password', 'name')
>>> verifier.load_key('certfile.cer', None, 'name', key_format='cert-pem')
>>> verifier.verify(xml)
True

Similarly, you can sign using the class. The key to be used can be specified by
providing the correct KeyName attribute. Otherwise, the first key is used.

Note that the full xmlsec library is not utilized and only limited signing and
verification are possible. Encryption/decryption has not been implemented,
neither has template support.
"""

__author__ = "Ralph Broenink"
__copyright__ = "Copyright 2013. Antagonist B.V."
__version__ = "0.2.1"
__date__ = "2013-06-19"

# For those feeling more comfortable using constants

BINARY = 'binary'
CERT_DER = 'cert-der'
CERT_PEM = 'cert-pem'
DER = 'der'
PEM = 'pem'
PKCS12 = 'pkcs12'
PKCS8_DER = 'pkcs8-der'
PKCS8_PEM = 'pkcs8-pem'

ANY = 'any'
NONE = 'none'
PERMANENT = 'permanent'
PRIVATE = 'private'
PUBLIC = 'public'
SESSION = 'session'
SYMMETRIC = 'symmetric'
TRUSTED = 'trusted'

# Some convenience methods

def sign(body, key_path, key_pass=None, key_name=None, key_format='pem', *args, **kwargs):
    """Convenience method to signing the provided xml using the provided key.
    
    body       -- A string containing an XML, already containing signature data.
    key_path   -- The path to a keyfile used to sign the XML.
    key_pass   -- The key password, or None if no password is set.
    key_name   -- The name to be set for the key, or None if none should be set
    key_format -- The format of the key as string.
    
    Available arguments for creating a template:
    
    canonicalization -- The c14n method, e.g. exc-c14n
    signing          -- The signing method, e.g. rsa-sha256
    references       -- A dict containing mappings of reference methods to
                        an iterable of transforms, e.g. 
                        {'sha256': ('enveloped-signature', )}
    key_name         -- This argument is present in the underlying 
                        XMLDSIG.load_key and XMLDSIG.sign methods. Take care 
                        to not include this argument with your call, the
                        argument will be passed to both methods if specified.
    key_x509         -- Boolean indicating whether X509 data is required.
    """
    
    xmldsig = XMLDSIG()
    xmldsig.load_key(key_path, key_pass, key_name, key_format=key_format)
    if key_name and (args or kwargs):
        kwargs['key_name'] = key_name
    return xmldsig.sign(body, *args, **kwargs)

def verify(body, key_path, key_pass=None, key_name=None, key_format='pem'):
    """Convenience method to verifying the provided xml using the provided key.
    If you only have a certificate, you may want to pass 'cert-pem' as your key
    format.
    
    body       -- A string containing an XML to be verified
    key_path   -- The path to a keyfile used to verify the XML.
    key_pass   -- The key password, or None if no password is set.
    key_name   -- The name to be set for the key, or None if none should be set
    key_format -- The format of the key as string.
    """
    
    xmldsig = XMLDSIG()
    xmldsig.load_key(key_path, key_pass, key_name, key_format=key_format)
    return xmldsig.verify(body)


class XMLDSIGError(Exception):
    """Thrown when something goes wrong inside the XMLDSIG class. This generally
    indicates some failure within the XMLDSIG module, but may also be caused by
    invalid paths, invalid key formats, or some other similar error. The xmlsec
    module will throw some information at you via stderr, most of the times this
    is garbage.
    """
    pass

class XMLDSIG(object):
    def __init__(self):
        """Creates a new XMLDSIG object. It will instantiate a local key 
        manager.
        """
        
        # Initialize the key manager
        self.key_manager = xmlsec.KeysMngr()
        
        if xmlsec.cryptoAppDefaultKeysMngrInit(self.key_manager) < 0:
            raise XMLDSIGError("Failed initializing the key manager")
    
    def __del__(self):
        """Destroys the key manager"""
        
        self.key_manager.destroy()
    
    
    #
    # key/cert loading
    #
        
    def load_key(self, path, password=None, name=None, cert_path=None, key_format='pem', cert_format='pem'):
        """Loads a key into the key store of the class.
        
        path       -- The path to a keyfile used to sign the XML.
        password   -- The key password, or None if no password is set.
        name       -- The name to be set for the key, or None if none should be set
        cert_path  -- The path to the certificate belonging to this key, or None
        key_format -- The format of the key as string. Defaults to pem
        cert_format-- The format of the certificate as string. Defaults to pem
        """
        
        key_format = XMLDSIG._determine_key_format(key_format)
        cert_format = XMLDSIG._determine_key_format(cert_format)
        
        try:
            # Load key
            key = xmlsec.cryptoAppKeyLoad(path, key_format, password, None, None)
            if key is None:
                raise XMLDSIGError('Failed loading private key %s' % path) 
            
            # Set key name
            if name and key.setName(name) < 0:
                raise XMLDSIGError('Failed setting key name of %s to %s' % (path, name))
            
            # Link certificate to key
            if cert_path and xmlsec.cryptoAppKeyCertLoad(key, cert_path, cert_format) < 0:
                raise XMLDSIGError('Failed loading certificate %s' % cert_path)
            
            # Load certificate into store
            if xmlsec.cryptoAppDefaultKeysMngrAdoptKey(self.key_manager, key) < 0:
                raise XMLDSIGError("Failed loading key %s into key manager." % path)
            
        except XMLDSIGError:
            raise
        except Exception as e:
            raise XMLDSIGError('Something went wrong loading key %s: %s' % (path, e))
    
    
    def load_cert(self, path, cert_format='pem', trust='trusted'):
        """Loads a certificate into the key manager.
        
        path        -- The path to the certificate
        cert_format -- The format of the certificate. Defaults to pem
        trust       -- Indicates the trust level of the certificate. Defaults to
                       trusted (other values not supported at this point)
        """
        
        cert_format = XMLDSIG._determine_key_format(cert_format)
        trust = XMLDSIG._determine_trust_format(trust)
        
        try:
            if self.key_manager.certLoad(path, xmlsec.KeyDataFormatPem, trust) < 0:
                raise XMLDSIGError("Failed loading certificate %s into key manager" % path)
        except XMLDSIGError:
            raise
        except Exception as e:
            raise XMLDSIGError('Something went wrong loading certificate %s: %s' % (path, e))
    
    def load_certs(self, paths, *args, **kwargs):
        """Loads a set of certificates. See load_cert for the possible other
        arguments.
        """
        
        for path in paths:
            self.load_cert(path, *args, **kwargs)
    
    #
    # signing and verification
    #
                
    def sign(self, body, *args, **kwargs):
        """Signs the provided XML body. The method will compile the XML into 
        libxml2 and provide a signature in the provided fields. You should 
        provide an XML containing Signature data. 
        
        body       -- A string containing an XML, already containing signature 
                      data.
                      
        If you pass more than one argument to this function, template_sign is 
        assumed.
        """
        
        if args or kwargs:
            return self.template_sign(body, *args, **kwargs)
        
        doc = dsig_ctx = None
        
        try:
            # parse the xml
            (doc, node) = XMLDSIG._parse_dsig_xml(body)
            
            # create a signing context
            dsig_ctx = self._create_dsig_ctx()
            
            # Sign
            if dsig_ctx.sign(node) < 0:
                raise XMLDSIGError('Failed signing the xml.')
            
            return doc.serialize('UTF-8', 0)  # 0 = not pretty
        
        except XMLDSIGError:
            raise
        except Exception as e:
            raise XMLDSIGError('Something went wrong signing the xml: %s' % e)
        
        finally:
            # Clear some space, it is a C API after all
            if dsig_ctx is not None:
                dsig_ctx.destroy()
            if doc is not None:
                doc.freeDoc()
                
    
    def template_sign(self, body, canonicalization, signing, references,
                      key_name=None, key_x509=False):
        """Signs a XML file and creates a template based on the information 
        provided. This information generally can be found in the documentation.
        
        body             -- The XML body string.
        canonicalization -- The c14n method, e.g. enc-c14n
        signing          -- The signing method, e.g. rsa-sha256
        references       -- A dict containing mappings of reference methods to
                            an iterable of transforms, e.g. 
                            {'sha256': ('enveloped-signature', )}
        key_name         -- The key name, or None if not required
        key_x509         -- Boolean indicating whether X509 data is required.
        """
        
        # Translate c14n and signing arguments
        canonicalization = XMLDSIG._determine_transform_format(canonicalization)
        signing = XMLDSIG._determine_transform_format(signing)
        
        doc = dsig_ctx = None
        
        try:
            
            # Reparse using libxml2
            doc = libxml2.parseDoc(body)
            if doc is None or doc.getRootElement() is None:
                raise XMLDSIGError("Failed feeding xml to libxml2")
            
            # Create signature template
            sign_node = xmlsec.TmplSignature(doc, canonicalization, signing, None)
            if sign_node is None:
                raise XMLDSIGError('Failed creating a signature template.')
            
            doc.getRootElement().addChild(sign_node)
            
            # Create references
            for (reference, transforms) in references.items():
                ref = XMLDSIG._determine_transform_format(reference)
                
                ref_node = sign_node.addReference(ref, None, None, None)
                if ref_node is None:
                    raise XMLDSIGError('Failed adding reference %s to template.' % reference)
                
                # add transforms
                for transform in transforms:
                    trans = XMLDSIG._determine_transform_format(transform)
                    
                    if ref_node.addTransform(trans) is None:
                        raise XMLDSIGError('Failed adding transform %s to template.' % transform)
            
            # Add keyinfo
            if key_name or key_x509:
                keyinfo_node = sign_node.ensureKeyInfo(None)
                if keyinfo_node is None:
                    raise XMLDSIGError('Failed adding key info to template.')
                
                if key_name:
                    if keyinfo_node.addKeyName(key_name) is None:
                        raise XMLDSIGError('Failed adding key name to template.')
                    
                if key_x509:
                    if keyinfo_node.addX509Data() is None:
                        raise XMLDSIGError('Failed adding X509 data to template.')
    
    
            # create a signing context
            dsig_ctx = self._create_dsig_ctx()
            
            # Sign
            if dsig_ctx.sign(sign_node) < 0:
                raise XMLDSIGError('Failed signing the xml.')
            
            return doc.serialize('UTF-8', 0)  # 0 = not pretty
        
        except XMLDSIGError:
            raise
        except Exception as e:
            raise XMLDSIGError('Something went wrong signing the xml: %s' % e)
        
        finally:
            # Clear some space, it is a C API after all
            if dsig_ctx is not None:
                dsig_ctx.destroy()
            if doc is not None:
                doc.freeDoc()
                
                
    def verify(self, body):
        """Verifies the provided XML body. Returns True when the signature is 
        valid, or False otherwise.
        
        body       -- A string containing an XML to be verified.
        """
        
        doc = dsig_ctx = None
        
        try:
            # parse the xml
            (doc, node) = XMLDSIG._parse_dsig_xml(body)
            
            # create a signing context
            dsig_ctx = self._create_dsig_ctx()
            
            if dsig_ctx.verify(node) < 0:
                raise XMLDSIGError('Failed verifying signature.')
            if dsig_ctx.status == xmlsec.DSigStatusSucceeded:
                return True
            else:
                return False
        
        except XMLDSIGError:
            raise
        except Exception as e:
            raise XMLDSIGError('Something went wrong verifying the xml: %s' % e)
        
        finally:
            # Clear some space, it is a C API after all
            if dsig_ctx is not None:
                dsig_ctx.destroy()
            if doc is not None:
                doc.freeDoc()
    
    #
    # helper methods
    #

    @staticmethod
    def _determine_trust_format(truststring):
        """Translates a string containing the format of the trust, to a pyXMLsec
        format.
        """
        
        if truststring == 'any':
            return xmlsec.KeyDataTypeAny
        elif truststring == 'none':
            return xmlsec.KeyDataTypeNone
        elif truststring == 'permanent':
            return xmlsec.KeyDataTypePermanent
        elif truststring == 'private':
            return xmlsec.KeyDataTypePrivate
        elif truststring == 'public':
            return xmlsec.KeyDataTypePublic
        elif truststring == 'session':
            return xmlsec.KeyDataTypeSession
        elif truststring == 'symmetric':
            return xmlsec.KeyDataTypeSymmetric
        elif truststring == 'trusted':
            return xmlsec.KeyDataTypeTrusted
        else:
            raise XMLDSIGError('Unknown trust format: %s' % truststring)
        
    @staticmethod
    def _determine_key_format(formatstring):
        """Translates a string containing the format of the key, to a pyXMLsec
        format.
        """
        
        if formatstring == 'binary':
            return xmlsec.KeyDataFormatBinary
        elif formatstring == 'cert-der':
            return xmlsec.KeyDataFormatCertDer
        elif formatstring == 'cert-pem':
            return xmlsec.KeyDataFormatCertPem
        elif formatstring == 'der':
            return xmlsec.KeyDataFormatDer
        elif formatstring == 'pem':
            return xmlsec.KeyDataFormatPem
        elif formatstring == 'pkcs12':
            return xmlsec.KeyDataFormatPkcs12
        elif formatstring == 'pkcs8-der':
            return xmlsec.KeyDataFormatPkcs8Der
        elif formatstring == 'pkcs8-pem':
            return xmlsec.KeyDataFormatPkcs8Pem
        else:
            raise XMLDSIGError('Unknown key format: %s' % formatstring)
        
    @staticmethod
    def _determine_transform_format(formatstring):
        """Translates strings to all transform methods of the pyXMLsec library.
        This should actually sort out which value could be used where, but for 
        now, it works :-).
        """
        if formatstring == 'aes128-cbc':
            result = xmlsec.transformAes128CbcId()
        elif formatstring == 'aes192-cbc':
            result = xmlsec.transformAes192CbcId()
        elif formatstring == 'aes256-cbc':
            result = xmlsec.transformAes256CbcId()
        elif formatstring == 'kw-aes128':
            result = xmlsec.transformKWAes128Id()
        elif formatstring == 'kw-aes192':
            result = xmlsec.transformKWAes192Id()
        elif formatstring == 'kw-aes256':
            result = xmlsec.transformKWAes256Id()
        elif formatstring == 'des3-cbc':
            result = xmlsec.transformDes3CbcId()
        elif formatstring == 'kw-des3':
            result = xmlsec.transformKWDes3Id()
        elif formatstring == 'dsa-sha1':
            result = xmlsec.transformDsaSha1Id()
        elif formatstring == 'hmac-md5':
            result = xmlsec.transformHmacMd5Id()
        elif formatstring == 'hmac-ripemd160':
            result = xmlsec.transformHmacRipemd160Id()
        elif formatstring == 'hmac-sha1':
            result = xmlsec.transformHmacSha1Id()
        elif formatstring == 'hmac-sha224':
            result = xmlsec.transformHmacSha224Id()
        elif formatstring == 'hmac-sha256':
            result = xmlsec.transformHmacSha256Id()
        elif formatstring == 'hmac-sha384':
            result = xmlsec.transformHmacSha384Id()
        elif formatstring == 'hmac-sha512':
            result = xmlsec.transformHmacSha512Id()
        elif formatstring == 'hmac-md5':
            result = xmlsec.transformMd5Id()
        elif formatstring == 'ripemd160':
            result = xmlsec.transformRipemd160Id()
        elif formatstring == 'rsa-md5':
            result = xmlsec.transformRsaMd5Id()
        elif formatstring == 'rsa-ripemd160':
            result = xmlsec.transformRsaRipemd160Id()
        elif formatstring == 'rsa-sha1':
            result = xmlsec.transformRsaSha1Id()
        elif formatstring == 'rsa-sha224':
            result = xmlsec.transformRsaSha224Id()
        elif formatstring == 'rsa-sha256':
            result = xmlsec.transformRsaSha256Id()
        elif formatstring == 'rsa-sha384':
            result = xmlsec.transformRsaSha384Id()
        elif formatstring == 'rsa-sha512':
            result = xmlsec.transformRsaSha512Id()
        elif formatstring == 'rsa-pkcs1':
            result = xmlsec.transformRsaPkcs1Id()
        elif formatstring == 'rsa-oaep':
            result = xmlsec.transformRsaOaepId()
        elif formatstring == 'sha1':
            result = xmlsec.transformSha1Id()
        elif formatstring == 'sha224':
            result = xmlsec.transformSha224Id()
        elif formatstring == 'sha256':
            result = xmlsec.transformSha256Id()
        elif formatstring == 'sha384':
            result = xmlsec.transformSha384Id()
        elif formatstring == 'sha512':
            result = xmlsec.transformSha512Id()
        elif formatstring == 'base64':
            result = xmlsec.transformBase64Id()
        elif formatstring == 'inc-c14n':
            result = xmlsec.transformInclC14NId()
        elif formatstring == 'inc-c14n-with-comments':
            result = xmlsec.transformInclC14NWithCommentsId()
        elif formatstring == 'exc-c14n':
            result = xmlsec.transformExclC14NId()
        elif formatstring == 'exc-c14n-with-comments':
            result = xmlsec.transformExclC14NWithCommentsId()
        elif formatstring in ('enveloped', 'enveloped-signature'):
            result = xmlsec.transformEnvelopedId()
        elif formatstring in ('xpath', 'xpath-19991116', 'xmldsig-filter'):
            result = xmlsec.transformXPathId()
        elif formatstring in ('xpath2', 'xmldsig-filter2'):
            result = xmlsec.transformXPath2Id()
        elif formatstring == 'xpointer':
            result = xmlsec.transformXPointerId()
        elif formatstring in ('xslt', 'xslt-19991116'):
            result = xmlsec.transformXsltId()
        elif formatstring == 'remove-xml-tags-transform':
            result = xmlsec.transformRemoveXmlTagsC14NId()
        elif formatstring == 'visa3d-hack':
            result = xmlsec.transformVisa3DHackId()
        else:
            raise XMLDSIGError('Unknown transform: %s' % formatstring)
        
        if result is None:
            raise XMLDSIGError('Transform %s not available' % formatstring)
        else:
            return result
            
    
    @staticmethod
    def _parse_dsig_xml(body):
        """Parse the given XML body into a libxml2 object, and retrieve the
        DSigNs node. Returns the libxml2 doc and node.
        """
        
        # Reparse using libxml2
        doc = libxml2.parseDoc(body)
        if doc is None or doc.getRootElement() is None:
            raise XMLDSIGError("Failed feeding xml to libxml2")
            
        # find the Signature node
        node = xmlsec.findNode(doc, xmlsec.NodeSignature, xmlsec.DSigNs)
        if node is None:
            raise XMLDSIGError("Failed finding signature root node.")
        
        return doc, node
    
    @staticmethod
    def _parse_enc_xml(body):
        """Parse the given XML body into a libxml2 object, and retrieve the
        EncNs node. Returns the libxml2 doc and node.
        """
        
        # Reparse using libxml2
        doc = libxml2.parseDoc(body)
        if doc is None or doc.getRootElement() is None:
            raise XMLDSIGError("Failed feeding xml to libxml2")
            
        # find the Signature node
        node = xmlsec.findNode(doc, xmlsec.NodeEncryptedData, xmlsec.EncNs)
        if node is None:
            raise XMLDSIGError("Failed finding encryption root node.")
        
        return doc, node
    
    def _create_dsig_ctx(self):
        """Creates a new DSig Ctx on the key manager. Remember to call .destroy
        on this object.
        """
        
        dsig_ctx = xmlsec.DSigCtx(self.key_manager)
        if dsig_ctx is None:
            raise XMLDSIGError('Failed creating signature context.')
        return dsig_ctx
    
    
    def _create_enc_ctx(self):
        """Creates a new Enc Ctx on the key manager. Remember to call .destroy
        on this object.
        """
        
        enc_ctx = xmlsec.EncCtx(self.key_manager)
        if enc_ctx is None:
            raise XMLDSIGError('Failed creating encryption context.')
        return enc_ctx
        
def _init():
    """Initializes the libxml2 parser and XMLSEC library. Is called
    automatically upon loading this module.
    """
    # Initiate the libxml2 parser
    libxml2.initParser()
    libxml2.substituteEntitiesDefault(1)
            
    # Initialize xmlsec
    if xmlsec.init() < 0:
        raise XMLDSIGError("Failed initializing xmlsec library")
    if xmlsec.cryptoAppInit(None) < 0:
        raise XMLDSIGError("Failed initializing crypto library")
    if xmlsec.cryptoInit() < 0:
        raise XMLDSIGError("Failed initializing xmlsec-crypto library")
    
_init()

def destroy():
    """Destroys the modules loaded by this module. Should be called after
    everything is done, but we won't kill you if you don't.
    """
    # The following commands are commented because this is bugged with
    # urllib2 (see https://github.com/dnet/pyxmlsec/issues/1)
    #xmlsec.cryptoShutdown()
    #xmlsec.cryptoAppShutdown()
        
    xmlsec.shutdown()
    libxml2.cleanupParser()