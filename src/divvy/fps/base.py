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

import string
import copy
import random
import logging
import time
import urllib2
import urllib

from divvy.fps import util
from divvy.fps import conf
from divvy.fps import xml

RANDOM = random.Random()

LOGGER = logging.getLogger("divvy.fps.base")

SANDBOX_ENDPOINT = 'https://fps.sandbox.amazonaws.com'
ENDPOINT = 'https://fps.amazonaws.com'

TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
AMAZON_FPS_API_VERSION = '2008-09-17'

class InvalidSignatureError(Exception):

    def __init__(self, message, signature, parameters):
        super(InvalidSignatureError, self).__init__(message)
        self.parameters, self.signature = parameters, signature

class SignatureValidator(object):
    """A signature validator"""

    def __init__(self, access_key_id=None, secret_key=None):
        access_key_id = access_key_id or conf.DEFAULT_ACCESS_KEY_ID
        secret_key = secret_key or conf.DEFAULT_SECRET_KEY

        assert access_key_id is not None, "access_key_id must be provided"
        assert secret_key is not None, "secret_key must be provided"
        self.access_key_id = access_key_id
        self.secret_key = secret_key

    def validate_signature(self, parameters, signature=None, raise_error=False, url_end_point=None):
        if conf.DEFAULT_SIGNATURE_VERSION == "2":
            assert url_end_point, "The url_end_point is a required parameter for version 2 Signatures."
            # @TODO - the api call won't work since api.py imports base.py (circular import).  Need to resolve circular import or implement PKI method (ugh!).
            #client = api.ApiClient()
            #response = client.verify_signature(url_end_point, parameters)
            http_parameters = urllib.urlencode(parameters)
            assert type(http_parameters) in [str, unicode], "http_parameters must be a string"
            self.endpoint = SANDBOX_ENDPOINT if conf.RUN_IN_SANDBOX else ENDPOINT
            timestamp = time.strftime(TIME_FORMAT, time.gmtime())
            qs = util.query_string({
                'Action':'VerifySignature',
                'Timestamp':timestamp,
                'AWSAccessKeyId': self.access_key_id,
                'Version': AMAZON_FPS_API_VERSION,
                'UrlEndPoint': url_end_point,
                'HttpParameters': http_parameters,})
            url = self.endpoint+'/'+qs

            try:
                data = urllib2.urlopen(url).read()
                response = xml.VerifySignatureResponse(data)
            except urllib2.HTTPError, e:
                data = e.read()
                response = xml.Response(data)

            try:
                matches = response.verificationStatus == 'Success'
            except AttributeError:
                matches = False
            if not matches:
                LOGGER.error("Signature Verification failed.")
                if raise_error:
                    raise InvalidSignatureError("Invalid Signature.", "", parameters)
            return matches
        else:
            if not (signature is not None or 'signature' in parameters):
                raise AssertionError("expected signature in parameters: %r" %parameters)
            parameters = copy.copy(parameters)
            signature = signature or parameters.pop('signature')
            sig_should_be = util.get_signature(self.secret_key, parameters, self.endpoint)
            matches = signature == sig_should_be
            if not matches:
                LOGGER.debug("Signatures did not match.  Expected %r but got %r",
                             sig_should_be, signature)
                if raise_error:
                    LOGGER.error("Invalid Signature %r for %r", signature, parameters)
                    raise InvalidSignatureError("Invalid Signature.", signature, parameters)
            return matches

class ParameterizedResponse(SignatureValidator):

    def __init__(self, parameters, access_key_id=None, secret_key=None, url_end_point=None):
        super(ParameterizedResponse, self).__init__(access_key_id=access_key_id,
                                                    secret_key=secret_key)
        parameters = parameters
        self.validate_signature(parameters, raise_error=True, url_end_point=url_end_point)
        self.parameters = parameters

class AmazonFPSClient(SignatureValidator):
    """Base class for all amazon FPS clients."""
