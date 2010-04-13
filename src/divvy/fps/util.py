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

def get_signature(key, parameters, endpoint=None):
    """Get a signature for FPS requests.

    Given a set of query parameters as a dict, this will compute a
    signature for use with amazon FPS as documented here:

    http://docs.amazonwebservices.com/AmazonFPS/2008-09-17/FPSAdvancedGuide/index.html?APPNDX_GeneratingaSignature.html

    """
    if 'signatureVersion' in parameters and parameters['signatureVersion'] == '2':
        #use Signature Version 2 *Preferred*
        return get_signature_v2(key, endpoint, parameters)
    else:
        #use Signature Version 1 -- ***will stop working after Nov 1, 2010***
        msg = "".join(("%s%s" % item
                       for item in sorted(parameters.items(), key=lambda item: item[0].lower())
                       if item[1] is not None))
        return base64.encodestring(hmac.new(key, msg, sha).digest()).strip()

def get_signature_v2(key, endpoint, parameters):
    """Get a version 2 signature for FPS requests.

    Given a set of query parameters as a dict, this will compute a
    signature for use with amazon FPS as documented here:

    http://docs.amazonwebservices.com/AmazonFPS/2008-09-17/FPSAdvancedGuide/index.html?APPNDX_GeneratingaSignature.html

    """
    if 'signatureMethod' in parameters and parameters['signatureMethod'] == 'HmacSHA1':
        hash_func = hashlib.sha1
    else:
        # signatureMethod = "HmacSHA256"
        hash_func = hashlib.sha256

    endpoint_parts = urllib2.urlparse.urlsplit(endpoint)

    string_to_sign = "GET\n"
    string_to_sign += endpoint_parts.hostname.lower() + "\n"
    if endpoint_parts.path == '':
        string_to_sign += "/\n"
    else:
        string_to_sign += endpoint_parts.path + "\n"
    string_to_sign += "&".join(("%s=%s" % (urllib.quote(item[0]), urllib.quote(item[1]),)
                   for item in sorted(parameters.items(), key=lambda item: item[0])
                   if item[1] is not None))

    return base64.encodestring(hmac.new(key, string_to_sign, hash_func).digest()).strip()
