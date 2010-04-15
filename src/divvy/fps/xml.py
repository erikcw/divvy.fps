from __future__ import absolute_import
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
import re
from xml.etree import ElementTree

def _tag(name):
    return '{http://fps.amazonaws.com/doc/2008-09-17/}%s' % name

NS_RE = re.compile(r'{([^}]*)}*')

class XmlObject(object):

    def __init__(self, xml):
        if isinstance(xml, (str, unicode)):
            self.xml = ElementTree.fromstring(xml)
        else:
            self.xml = xml
        self.parse()

    def tag(self, name, ns=None):
        if ns is None:
            match = NS_RE.match(self.xml.tag)
            if match:
                ns = match.groups()[0]
        if ns is None:
            return name
        else:
            return "{%s}%s" % (ns, name)

    def parse(self):
        pass

class ResponseError(XmlObject):

    @property
    def code(self):
        return self.xml.find(self.tag("Code")).text

    @property
    def message(self):
        return self.xml.find(self.tag("Message")).text

class ResponseMetadata(XmlObject):

    @property
    def requestId(self):
        return self.xml.find(self.tag("RequestId")).text

class Response(XmlObject):
    def parse(self):
        self.metadata = ResponseMetadata(self.xml.find(self.tag("ResponseMetadata")))

        self.errors = []
        errorsXml = self.xml.find(self.tag("Errors"))
        if errorsXml:
            for errorXml in errorsXml.findall(self.tag("Error")):
                self.errors.append(ResponseError(errorXml))

    def __repr__(self):
        return "<%s %r errors>" % (self.__class__.__name__, len(self.errors))

class PayResponse(Response):

    def __init__(self, xmlstring):
        super(PayResponse, self).__init__(xmlstring)

        pay_result = self.xml.find(self.tag('PayResult'))
        self.transactionId = pay_result.find(self.tag('TransactionId')).text
        self.transactionStatus = pay_result.find(self.tag('TransactionStatus')).text

    def __repr__(self):
        return "<%s transactionId=%r transactionStatus=%r>" % (self.__class__.__name__,
                                                               self.transactionId,
                                                               self.transactionStatus)


class VerifySignatureResponse(Response):
    """<?xml version="1.0"?>
       <VerifySignatureResponse xmlns="http://fps.amazonaws.com/doc/2008-09-17/">
        <VerifySignatureResult>
         <VerificationStatus>Success</VerificationStatus>
        </VerifySignatureResult>
        <ResponseMetadata>
         <RequestId>5f93bd31-739c-48a2-9559-359c2c55b8ec:0</RequestId>
        </ResponseMetadata>
       </VerifySignatureResponse>"""
    def __init__(self, xmlstring):
        super(VerifySignatureResponse, self).__init__(xmlstring)

        verify_signature_result = self.xml.find(self.tag('VerifySignatureResult'))
        self.verificationStatus = verify_signature_result.find(self.tag('VerificationStatus')).text
        self.requestId = self.xml.find(self.tag('ResponseMetadata')).find(self.tag('RequestId')).text

    def __repr__(self):
        return "<%s requestId=%r verificationStatus=%r>" % (self.__class__.__name__,
                                                               self.requestId,
                                                               self.verificationStatus)

