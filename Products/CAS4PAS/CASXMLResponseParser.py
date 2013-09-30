# -*- coding: utf-8 -*-
""" Parse CAS Response
"""

from HTMLParser import HTMLParser, HTMLParseError

class CASXMLResponseParser(HTMLParser):
    """
    Class used to parse XML response from CAS server.
    It currently works with cas server 2.0.12 from yale.

    it works by raising two types of exceptions :
        - "user", username
        - "failure", failure_message
    """

    _user = 0
    _user_data = None
    _failure = 0
    _failure_data = None
    _attributes = 0
    _attributes_data = {}
    _attr_key = None

    def resetAttributes(self):
        self._user = 0
        self._user_data = None
        self._failure = 0
        self._failure_data = None
        self._attributes = 0
        self._attributes_data = {}
        self._attr_key = None

    def handle_starttag(self, tag, attrs):
        # tag is returned lowercase
        if tag == 'cas:user' or tag == 'user':
            self._user = 1
        elif tag == 'cas:authenticationfailure' or \
             tag == 'authenticationfailure':
            self._failure = 1
        elif tag == 'cas:attributes':
            self._attributes = 1
        elif self._attributes == 1:
            self._attr_key = tag[4:]
        else:
            # leave this here as handle_data may be called several times
            # for the same node
            self._user = 0
            self._failure = 0

    def handle_data(self, data):
        if self._user == 1:
            self._user_data = (self._user_data or "") + data.strip()
        if self._failure == 1:
            self._failure_data = (self._failure_data or "") + data.strip()
        if self._attributes == 1 and len(data.strip()) > 0:
            if self._attr_key in self._attributes_data.keys():
                self._attributes_data[self._attr_key] += data.strip()
            else:
                self._attributes_data[self._attr_key] = data.strip()

    def handle_endtag(self, tag):
        if tag == 'cas:attributes':
            self._attributes = 0
        if tag == 'cas:user':
            self._user = 0

    def getUser(self):
        return self._user_data

    def getFailure(self):
        return self._failure_data

    def getAttributes(self):
        return self._attributes_data


# a little test usable outside Zope plus a use case
if __name__ == "__main__":
    XML_OK = """
        <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
          <cas:authenticationSuccess>
            <cas:user>joeblack</cas:user>
              <cas:proxyGrantingTicket>PGTIOU-84678-8a9d...
            </cas:proxyGrantingTicket>
          </cas:authenticationSuccess>
        </cas:serviceResponse>"""

    XML_FAILURE = """
        <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
          <cas:authenticationFailure code='INVALID_REQUEST'>
            'service' and 'ticket' parameters are both required
          </cas:authenticationFailure>
        </cas:serviceResponse>"""
    try:
        parser = CASXMLResponseParser()
        parser.feed(XML_OK)
        if parser.getUser() == "joeblack":
            print "Test getUser    => OK"
        else:
            print "Test getUser    => FAIL (%s)" % parser.getUser()

        parser = CASXMLResponseParser()
        parser.feed(XML_FAILURE)
        bad_msg = "'service' and 'ticket' parameters are both required"
        if parser.getFailure() == bad_msg:
            print "Test getFailure => OK"
        else:
            print "Test getFailure => FAIL"
    except HTMLParseError, e:
        print "XML Parsing exception: " + str(e)

