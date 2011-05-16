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

