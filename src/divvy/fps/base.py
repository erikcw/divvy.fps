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

from divvy.fps import util
from divvy.fps import conf

RANDOM = random.Random()

LOGGER = logging.getLogger("divvy.fps.base")

class InvalidSignatureError(Exception):

    def __init__(self, message, signature, parameters):
        super(InvalidSignatureError, self).__init__(message)
        self.parameters, self.signature = parameters, signature

class SignatureValidator(object):
    """A signature validator"""

    def __init__(self,access_key_id=None, secret_key=None):
        access_key_id = access_key_id or conf.DEFAULT_ACCESS_KEY_ID
        secret_key = secret_key or conf.DEFAULT_SECRET_KEY

        assert access_key_id is not None, "access_key_id must be provided"
        assert secret_key is not None, "secret_key must be provided"
        self.access_key_id = access_key_id
        self.secret_key = secret_key

    def validate_signature(self, parameters, signature=None, raise_error=False):
        if not (signature is not None or 'signature' in parameters):
            raise AssertionError("expected signature in parameters: %r" %parameters)
        parameters = copy.copy(parameters)
        signature = signature or parameters.pop('signature')
        sig_should_be = util.get_signature(self.secret_key, parameters)
        matches = signature == sig_should_be
        if not matches:
            LOGGER.debug("Signatures did not match.  Expected %r but got %r",
                         sig_should_be, signature)
            if raise_error:
                LOGGER.error("Invalid Signature %r for %r", signature, parameters)
                raise InvalidSignatureError("Invalid Signature.", signature, parameters)
        return matches

class ParameterizedResponse(SignatureValidator):

    def __init__(self, parameters, access_key_id=None, secret_key=None):
        super(ParameterizedResponse, self).__init__(access_key_id=access_key_id,
                                                    secret_key=secret_key)
        parameters = parameters
        self.validate_signature(parameters, raise_error=True)
        self.parameters = parameters

class AmazonFPSClient(SignatureValidator):
    """Base class for all amazon FPS clients."""
