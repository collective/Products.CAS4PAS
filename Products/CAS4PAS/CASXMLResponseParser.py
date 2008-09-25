
from HTMLParser import HTMLParser,HTMLParseError

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


    def handle_starttag(self, tag, attrs):
        # tag is returned lowercase
        if tag == 'cas:user' or tag == 'user':
            self._user = 1
        elif tag == 'cas:authenticationfailure' or tag == 'authenticationfailure':
            self._failure = 1
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

    def handle_endtag(self, tag):
            pass

    def getUser(self):
        return self._user_data

    def getFailure(self):
        return self._failure_data

# a little test usable outside Zope plus a use case
if __name__ == "__main__":
    xml_ok="""
        <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
          <cas:authenticationSuccess>
            <cas:user>joeblack</cas:user>
              <cas:proxyGrantingTicket>PGTIOU-84678-8a9d...
            </cas:proxyGrantingTicket>
          </cas:authenticationSuccess>
        </cas:serviceResponse>"""
    xml_failure="""
        <cas:serviceResponse xmlns:cas='http://www.yale.edu/tp/cas'>
          <cas:authenticationFailure code='INVALID_REQUEST'>
            'service' and 'ticket' parameters are both required
          </cas:authenticationFailure>
        </cas:serviceResponse>"""
    try:
        parser = CASXMLResponseParser()
        parser.feed(xml_ok)
        if parser.getUser() == "joeblack":
            print "Test getUser    => OK"
        else:
            print "Test getUser    => FAIL (%s)" % parser.getUser()

        parser = CASXMLResponseParser()
        parser.feed(xml_failure)
        if parser.getFailure() == "'service' and 'ticket' parameters are both required":
            print "Test getFailure => OK"
        else:
            print "Test getFailure => FAIL"
    except HTMLParseError, e:
        print "XML Parsing exception: " + str(e)

