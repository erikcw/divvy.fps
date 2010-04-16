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

import logging
import urllib
import uuid

from divvy.fps import base
from divvy.fps import util
from divvy.fps import conf

LOGGER = logging.getLogger("divvy.fps.authorization")
LOGO = "logo"
BANNER = "banner"

class Pipelines:
    SINGLE_USE = "SingleUse"
    MULTI_USE = "MultiUse"
    RECURRING = "Recurring"
    RECIPIENT = "Recipient"
    SETUP_PREPAID = "SetupPrepaid"
    SETUP_POSTPAID = "SetupPostpaid"
    EDIT_TOKEN = "EditToken"

class SingleUseStatusCodes:
    SUCCESS_BALANCE_TRANSFER = "SA"
    SUCCESS_BANK_TRANSFER = "SB"
    SUCCESS_CREDIT_CARD = "SC"
    SYSTEM_ERROR = "SE"
    ABORTED = "A"
    ERROR = "CE"
    PAYMENT_METHOD_MISMATCH = "PE"
    UNSUPPORTED_PAYMENT_METHOD = "NP"
    NOT_REGISTERED = "NM"

class RecurringUseStatusCodes:
    SUCCESS_BALANCE_TRANSFER = "SA"
    SUCCESS_BANK_TRANSFER = "SB"
    SUCCESS_CREDIT_CARD = "SC"
    SYSTEM_ERROR = "SE"
    ABORTED = "A"
    ERROR = "CE"
    PAYMENT_METHOD_MISMATCH = "PE"
    UNSUPPORTED_PAYMENT_METHOD = "NP"
    NOT_REGISTERED = "NM"

SANDBOX_ENDPOINT = "https://authorize.payments-sandbox.amazon.com/cobranded-ui/actions/start"
ENDPOINT = "https://authorize.payments.amazon.com/cobranded-ui/actions/start"
AMAZON_FPS_VERSION = '2009-01-09'

class AuthorizationClient(base.AmazonFPSClient):
    """Client for handling payment authorization."""

    def __init__(self,access_key_id=None,secret_key=None,endpoint=None):
        super(AuthorizationClient, self).__init__(access_key_id=access_key_id, secret_key=secret_key)

        if endpoint is None:
            endpoint = SANDBOX_ENDPOINT if conf.RUN_IN_SANDBOX else ENDPOINT
        self.endpoint = endpoint

    def get_query_string(self, parameters):
        """Return a query string for the given keyword arguments.

        This will include the correct calleryKey, version, and
        generated query signature needed by amazon.
        """
        parameters.setdefault('callerKey', self.access_key_id)
        parameters.setdefault('version', AMAZON_FPS_VERSION)
        parameters.setdefault('signatureVersion', '2')
        if parameters['signatureVersion'] == '2':
            parameters.setdefault('signatureMethod', 'HmacSHA256')
            parameters['signature'] = util.get_signature(self.secret_key, parameters, self.endpoint)
        else:
            parameters['awsSignature'] = util.get_signature(self.secret_key, parameters, self.endpoint)
        return util.query_string(parameters)

    def authorize_single_use_token(self, returnUrl, transactionAmount,
                                   addressName=None, addressLine1=None,
                                   addressLine2=None, city=None,
                                   state=None, zip=None,
                                   phoneNumber=None, collectShippingAddress=None,
                                   currencyCode=None, discount=None,
                                   giftWrapping=None, handling=None,
                                   itemTotal=None, paymentMethod=None,
                                   paymentReason=None, reserve=None,
                                   shipping=None, tax=None,
                                   cobrandingStyle=None, cobrandingUrl=None,
                                   callerReference=None, websiteDescription=None):
        assert cobrandingStyle is None or cobrandingStyle in (LOGO, BANNER)
        cobrandingUrl = cobrandingUrl or conf.DEFAULT_COBRANDING_URL
        if callerReference is None:
            callerReference = self.get_caller_reference()
        qs = self.get_query_string({
                'addressName':addressName,
                'addressLine1':addressLine1,
                'addressLine2':addressLine2,
                'city':city,
                'state':state,
                'zip':zip,
                'phoneNumber':phoneNumber,
                'collectShippingAddress':collectShippingAddress,
                'currencyCode':currencyCode,
                'discount':discount,
                'giftWrapping':giftWrapping,
                'handling':handling,
                'itemTotal':itemTotal,
                'paymentMethod':paymentMethod,
                'paymentReason':paymentReason,
                'reserve':reserve,
                'shipping':shipping,
                'tax':tax,

                'callerReference':callerReference,
                'cobrandingStyle':cobrandingStyle,
                'cobrandingUrl':cobrandingUrl,

                'pipelineName':Pipelines.SINGLE_USE,
                'returnUrl':returnUrl,
                'transactionAmount':transactionAmount,
                'websiteDescription':websiteDescription,
                })
        LOGGER.info("Getting singule use token with qs %s", qs)
        url = self.endpoint + qs
        return callerReference, url

    def authorize_recurring_use_token(self, returnUrl, transactionAmount, recurringPeriod,
                                   addressName=None, addressLine1=None,
                                   addressLine2=None, city=None,
                                   state=None, zip=None,
                                   phoneNumber=None, collectShippingAddress=None,
                                   currencyCode=None, discount=None,
                                   giftWrapping=None, handling=None,
                                   itemTotal=None, paymentMethod=None,
                                   paymentReason=None, reserve=None,
                                   shipping=None, tax=None,
                                   cobrandingStyle=None, cobrandingUrl=None,
                                   callerReference=None, websiteDescription=None):
        assert cobrandingStyle is None or cobrandingStyle in (LOGO, BANNER)
        cobrandingUrl = cobrandingUrl or conf.DEFAULT_COBRANDING_URL
        if callerReference is None:
            callerReference = self.get_caller_reference()
        qs = self.get_query_string({
                'addressName':addressName,
                'addressLine1':addressLine1,
                'addressLine2':addressLine2,
                'city':city,
                'state':state,
                'zip':zip,
                'phoneNumber':phoneNumber,
                'collectShippingAddress':collectShippingAddress,
                'currencyCode':currencyCode,
                'discount':discount,
                'giftWrapping':giftWrapping,
                'handling':handling,
                'itemTotal':itemTotal,
                'paymentMethod':paymentMethod,
                'paymentReason':paymentReason,
                'reserve':reserve,
                'shipping':shipping,
                'tax':tax,

                'recurringPeriod':recurringPeriod,

                'callerReference':callerReference,
                'cobrandingStyle':cobrandingStyle,
                'cobrandingUrl':cobrandingUrl,

                'pipelineName':Pipelines.RECURRING,
                'returnUrl':returnUrl,
                'transactionAmount':transactionAmount,
                'websiteDescription':websiteDescription,
                })
        LOGGER.info("Getting recurring use token with qs %s", qs)
        url = self.endpoint + qs
        return callerReference, url

    def get_caller_reference(self):
        """Return a suitably random caller reference string."""
        return str(uuid.uuid4())


class SingleUseTokenResponse(base.ParameterizedResponse):
    """A single use authorization response."""

    SUCCESS_CODES = (
        SingleUseStatusCodes.SUCCESS_BALANCE_TRANSFER,
        SingleUseStatusCodes.SUCCESS_BANK_TRANSFER,
        SingleUseStatusCodes.SUCCESS_CREDIT_CARD,
        )

    @property
    def is_success(self):
        return self.status in self.SUCCESS_CODES

    @property
    def status(self):
        return self.parameters.get("status")

    @property
    def caller_reference(self):
        return self.parameters['callerReference']

    @property
    def token_id(self):
        return self.parameters['tokenID']

    @property
    def error_message(self):
        return self.parameters.get("errorMessage")


class RecurringUseTokenResponse(base.ParameterizedResponse):
    """A recurring use authorization response."""

    def __init__(self, parameters, access_key_id=None, secret_key=None, url_end_point=None):
        self.endpoint = SANDBOX_ENDPOINT if conf.RUN_IN_SANDBOX else ENDPOINT
        super(RecurringUseTokenResponse, self).__init__(parameters, access_key_id=access_key_id, secret_key=secret_key, url_end_point=url_end_point)

    SUCCESS_CODES = (
        RecurringUseStatusCodes.SUCCESS_BALANCE_TRANSFER,
        RecurringUseStatusCodes.SUCCESS_BANK_TRANSFER,
        RecurringUseStatusCodes.SUCCESS_CREDIT_CARD,
        )

    @property
    def is_success(self):
        return self.status in self.SUCCESS_CODES

    @property
    def status(self):
        return self.parameters.get("status")

    @property
    def caller_reference(self):
        return self.parameters['callerReference']

    @property
    def token_id(self):
        return self.parameters['tokenID']

    @property
    def error_message(self):
        return self.parameters.get("errorMessage")
