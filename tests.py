import os
import unittest
import xmldsig

PEM_FILE = os.path.join(os.path.dirname(__file__), 'testcerts', 'test.pem')

EXAMPLE_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="urn:envelope">
  <Data>
    Hello, World!
  </Data>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
      <Reference URI="">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
        <DigestValue></DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue/>
    <KeyInfo>
      <KeyName/>
    </KeyInfo>
  </Signature>
</Envelope>
"""

EXAMPLE_XML_SIGNED = """<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="urn:envelope">
  <Data>
    Hello, World!
  </Data>
  <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    <SignedInfo>
      <CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
      <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <Reference URI="">
        <Transforms>
          <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
        </Transforms>
        <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <DigestValue>VweSIbNEl2P2r6lm+OL7hVJTwt8=</DigestValue>
      </Reference>
    </SignedInfo>
    <SignatureValue>R48EjTRYEN2XAcDKYH6yyiENnxJgM0f78hN2e99pu/12ihYx+7S11YZJ3rO9Du4b
qvrJw8NTcwghp751GJqVA5BH2RBcuPa8VaCPtUGArMxzjYg17dx0ZY5Kepx15m/a
1UvR5u+1fMjKDN3lTKSGvVxKnd56Q0S7S+G2ahBo4bHAdDaG2/yG90akbFT/KEZG
2IjpWKLOQJM0UHmmC93dZu9lQPa6F59+M3ALpHZ5GL9LhI7M9DsZ7nRcBXxSWe4G
xY6f8uotioNk5qHoVddEb0ms0Vxvdamw3JsqlMQCBz6/lWOTOhNmmp9D+fCmiP53
XY0n7o/cBwEgW4WNAGILNw==</SignatureValue>
    <KeyInfo>
      <KeyName>foo</KeyName>
    </KeyInfo>
  </Signature>
</Envelope>
"""

class TemplateTest(unittest.TestCase):
    def test_signing(self):
        signer = xmldsig.XMLDSIG()
        signer.load_key(path=PEM_FILE, password='foobar', name='foo')
        
        result = signer.sign(EXAMPLE_XML)
        self.assertEqual(result, EXAMPLE_XML_SIGNED)
        
    def test_signing_short(self):
        xmldsig.sign(EXAMPLE_XML, PEM_FILE, 'foobar', 'foo')
        # do not test result, as we assume an exception is thrown when something is off
        # we want to prevent duplicate errors with test_signing here
        
    def test_verification(self):
        verifier = xmldsig.XMLDSIG()
        verifier.load_key(path=PEM_FILE, password='foobar', name='foo')
        
        result = verifier.verify(EXAMPLE_XML_SIGNED)
        self.assertTrue(result)
        
    def test_template_verification_short(self):
        result = xmldsig.verify(EXAMPLE_XML_SIGNED, PEM_FILE, 'foobar')
        self.assertTrue(result)
    
if __name__ == '__main__':
    unittest.main()