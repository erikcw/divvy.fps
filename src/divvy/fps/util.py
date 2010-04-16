########################################################################
# Copyright (c) 2009 Paul Carduner and Contributors
# All Rights Reserved
# This file is part of divvy.fps.
#
# divvy.fps is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# divvy.fps is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with divvy.fps.  If not, see
# <http://www.gnu.org/licenses/>.
#########################################################################

import urllib
import hmac
import hashlib
import sha
import base64
import urllib2

def query_string(parameters):
    return "?"+urllib.urlencode(sorted([item for item in parameters.items()
                                        if item[1] is not None]))

def get_signature(key, parameters, endpoint=None, http_method="GET"):
    """Get a signature for FPS requests.

    Given a set of query parameters as a dict, this will compute a
    signature for use with amazon FPS as documented here:

    http://docs.amazonwebservices.com/AmazonFPS/2008-09-17/FPSAdvancedGuide/index.html?APPNDX_GeneratingaSignature.html

    """
    signatureVersion = parameters.get('SignatureVersion', '1')
    algorithm = hashlib.sha1

    print parameters, signatureVersion

    if signatureVersion == '2':
        #use Signature Version 2 *Preferred*
        if parameters.get('SignatureMethod') == 'HmacSHA256':
            algorithm = hashlib.sha256
        string_to_sign = calculate_string_to_sign_v2(http_method, endpoint, parameters)
    else:
        #use Signature Version 1 -- ***will stop working after Nov 1, 2010***
        string_to_sign = calculate_string_to_sign_v1(parameters)

    return sign(string_to_sign, key, algorithm)

def sign(data, key, algorithm):
    return base64.encodestring(hmac.new(key, data, algorithm).digest()).strip()

def calculate_string_to_sign_v1(parameters):
    msg = "".join(("%s%s" % item
                   for item in sorted(parameters.items(), key=lambda item: item[0].lower())
                   if item[1] is not None))
    return msg

def calculate_string_to_sign_v2(http_method, endpoint, parameters):
    """Get a version 2 signature for FPS requests.

    Given a set of query parameters as a dict, this will compute a
    signature for use with amazon FPS as documented here:

    http://docs.amazonwebservices.com/AmazonFPS/2008-09-17/FPSAdvancedGuide/index.html?APPNDX_GeneratingaSignature.html

    """

    assert http_method != None, "http_method cannot be None"
    endpoint_parts = urllib2.urlparse.urlsplit(endpoint)
    hostname = endpoint_parts.hostname
    uri = endpoint_parts.path

    string_to_sign = []
    string_to_sign.append(http_method)
    string_to_sign.append("\n")

    if hostname == None:
        string_to_sign.append("")
    else:
        string_to_sign.append(hostname.lower())
    string_to_sign.append("\n")

    if uri == None or len(uri.strip()) == 0:
        string_to_sign.append("/")
    else:
        string_to_sign.append(endpoint_parts.path)
    string_to_sign.append("\n")

    string_to_sign.append("&".join(("%s=%s" % (url_encode(item[0]), url_encode(item[1]),)
                   for item in sorted(parameters.items(), key=lambda item: item[0])
                   if item[1] is not None)))

    return "".join(string_to_sign)

def url_encode(value, is_path=False):
    encoded = urllib.quote(value)
    if is_path:
        encoded = encoded.replace("%2F", "/")
    else:
        encoded = encoded.replace("/", "%2F")
    return encoded

#def validate_signature_v2(parameters, url_endpoint, http_method):
#    """Verifies signature using PKI."""
#    assert 'signature' in parameters, "'signature' is missing from the parameters."
#    assert 'signatureMethod' in parameters, "'signatureMethod' is missing from the parameters."
#    assert parameters['signatureMethod'] == "RSA-SHA1", "'signatureMethod' present in parameters is invalid. Valid signatureMethods are : 'RSA-SHA1'"
#    assert 'certificateUrl' in parameters, "'certificateUrl' is missing from the parameters."
#
#    certificate = get_public_key_certificate_as_string(parameters['certificateUrl'])
#
#    # calculate the string to sign.
#    string_to_sign = calculate_string_to_sign_v2(http_method, url_endpoint, parameters)
#    
#def get_public_key_certificate_as_string(certificate_url):
#    # @TODO: implement caching
#    #@TODO: get from cache
#
#    opener = urllib2.build_opener(IgnoreRedirectHandler())
#    result = opener.open(urllib2.Request(certificate_url)).read()
#
#    #@TODO: store in cache
#    return result
#
#    
#
#class IgnoreRedirectHandler(urllib2.HTTPRedirectHandler):
#    """This redirect handler will ignore redirects by raising an exception if they occur.
#    This is used as a security feature and is recommended by Amazon for PKI signature verifiction."""
#
#    def http_error_301(self, req, fp, code, msg, headers):
#        raise "This urlopener is setup to ignore Redirects"
#
#    def http_error_302(self, req, fp, code, msg, headers):
#        raise "This urlopener is setup to ignore Redirects"
