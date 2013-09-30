# -*- coding: utf-8 -*-
#
# $Id$
""

from HTMLParser import HTMLParseError
import random
import string
import urllib

from zLOG import LOG, ERROR, DEBUG
from AccessControl.SecurityInfo import ClassSecurityInfo
from OFS.PropertyManager import PropertyManager
from App.class_init import default__class_init__ as InitializeClass
from Products.CMFPlone.utils import getToolByName
from Products.PageTemplates.PageTemplateFile import PageTemplateFile

from Products.PluggableAuthService.plugins.BasePlugin import BasePlugin
from Products.PluggableAuthService.utils import classImplements
from Products.PluggableAuthService.interfaces.plugins import \
        IExtractionPlugin, IChallengePlugin, IAuthenticationPlugin, \
        ICredentialsResetPlugin

from CASXMLResponseParser import CASXMLResponseParser

try: 
    # Plone 4 and higher 
    import plone.app.upgrade 
    PLONE_VERSION = 4 
except ImportError: 
    PLONE_VERSION = 3

addCASAuthHelperForm = PageTemplateFile(
    'zmi/addCASAuthHelperForm.zpt', globals())

class ProtectedAuthInfo:
    """An object where the username is not accessible from user code

    This object prevents the user name to be accessed or changed from
    anything by protected code. This means that we can always be sure
    that the username returned from _getUsername() has not been
    compromised by user code. This means we can store this object in a
    session, to have a session authentication.
    """

    def _setAuthInfo(self, authinfo):
        self.__authinfo = authinfo

    def _getAuthInfo(self):
        return self.__authinfo


def addCASAuthHelper( dispatcher
                       , id
                       , title=None
                       , REQUEST=None
                       ):
    """ Add a CASAuthHelper to a Pluggable Auth Service. """
    sp = CASAuthHelper(id, title)
    dispatcher._setObject(sp.getId(), sp)

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect( '%s/manage_workspace'
                                      '?manage_tabs_message='
                                      'CASAuthHelper+added.'
                                    % dispatcher.absolute_url() )


class CASAuthHelper(PropertyManager, BasePlugin):
    """ Multi-plugin for managing details of CAS Authentication. """

    meta_type = 'CAS Auth Helper'
    login_url = 'https://your.cas.server:port/cas/login'
    logout_url = 'https://your.cas.server:port/cas/logout'
    validate_url = 'https://your.cas.server:port/cas/validate'
    session_var = '__ac'
    gateway_mode = False

    security = ClassSecurityInfo()

    _properties = ( { 'id'    : 'title'
                    , 'label' : 'Title'
                    , 'type'  : 'string'
                    , 'mode'  : 'w'
                    }
                  , { 'id'    : 'login_url'
                    , 'label' : 'CAS Login URL'
                    , 'type'  : 'string'
                    , 'mode'  : 'w'
                    }
                  , { 'id'    : 'logout_url'
                    , 'label' : 'CAS Logout URL'
                    , 'type'  : 'string'
                    , 'mode'  : 'w'
                    }
                  , {'id'     : 'validate_url',
                     'type'   : 'string',
                     'label'  : 'Ticket validation URL',
                     'mode'   : 'w',
                    }
                  , {'id'     : 'session_var',
                     'type'   : 'string',
                     'label'  : 'Session credentials id',
                     'mode'   : 'w',
                    }
                  , {'id'     : 'gateway_mode',
                     'type'   : 'boolean',
                     'label'  : "Use CAS gateway mode (no login page)",
                     'mode'   : 'w',
                    }
                  )

    manage_options = ( BasePlugin.manage_options[:1] + \
                       PropertyManager.manage_options + \
                       BasePlugin.manage_options[2:]
                     )

    def __init__(self, id, title=None):
        self._setId(id)
        self.title = title

    security.declarePrivate('extractCredentials')
    def extractCredentials(self, request):
        """ Extract credentials from session or 'request'. """
        creds = {}
        username = None
        LOG("CAS4PAS extractCredentials", DEBUG, repr(request.form.items()))

        # Do not create sessions for anonymous user requests
        session = None
        sdm = getattr(self, 'session_data_manager', None)
        if sdm is not None:
            session = sdm.getSessionData(create=0)

        # First check if we have a ProtectedAuthInfo in the session
        if session is not None:
            ob = session.get(self.session_var)
            if ob is not None and isinstance(ob, ProtectedAuthInfo):
                username = ob._getAuthInfo()

        if username is None:
            # Not already authenticated. Is there a ticket in the URL?
            ticket = request.form.get('ticket')
            service = self.getService(request)
            if ticket is None:
                if not self.gateway_mode:
                    return None # No CAS authentification

                url = self.getLoginURL()
                request.response.redirect('%s?gateway=true&service=%s' % (url, service+'&amp;cas_gateway=true'), lock=1)
                return None # No CAS authentification
            username = self.validateTicket(service, ticket)
            if username is None:
                return None # Invalid CAS ticket

            # Add domain to avoid conflict with source_users logins
            if username.find('#') == -1:
                username = 'cas#' + username
            # # is an illegal character for user's login
            username = username.replace('#', '_')

            if PLONE_VERSION >= 4:
                creds['source'] = 'plone.session'
                self.session._setupSession(username, request.response)

            else:
                cookie = self.session.source.createIdentifier(username)
                creds['cookie'] = cookie
                creds['source'] = 'plone.session'
                self.session.setupSession(username, request.response)

        mtool = getToolByName(self, 'portal_membership')
        if mtool.getMemberById(username) is None:
            regtool = getToolByName(self, 'portal_registration')
            # Generate a random password so the user cannot connect without password
            # if source_users authentication is still enabled
            password = ''.join(random.choice(string.printable) for x in range(16))
            regtool.addMember(username, password)

        creds['login'] = username
        return creds

    def validateTicket(self, service, ticket):
        # prepare the GET parameters for checking the login
        checkparams = "?service=" + service + "&ticket=" + ticket
        # check the ticket
        casdata = urllib.URLopener().open(self.validate_url + checkparams)
        test = casdata.readline().strip()
        while len(test) == 0:
            test = casdata.readline()
            if len(test) == 0:
                break
            test = test.strip()
        if test == 'yes':
            # user is validated (CAS architecture 1.0)
            username = casdata.readline().strip()
            return username
        elif test.lower().find("cas:serviceresponse") > 0:
            # We have an XML response (CAS architecture 2.0)
            try:
                parser = CASXMLResponseParser()
                parser.resetAttributes()
                while test:
                    parser.feed(test)
                    test = casdata.readline()
                if parser.getUser():
                    attributes = parser.getAttributes()
                    sdm = getToolByName(self, 'session_data_manager')
                    session = sdm.getSessionData(create=True)
                    session.set('cas_attributes', attributes)
                    return parser.getUser()
                if parser.getFailure():
                    LOG("CAS4PAS", ERROR,
                        "Cannot validate ticket: %s [service=%s]" % (
                            parser.getFailure(), service))
                else:
                    LOG("CAS4PAS", ERROR, "CASXMLResponseParser couldn't " \
                                         "understand CAS server response")
            except HTMLParseError, e:
                LOG("CAS4PAS", ERROR,
                    "Error parsing ticket validation response: " + str(e))
            return None
        else:
            LOG("CAS4PAS", ERROR,
                "ticket validation: some unknown authentication error occurred")
            return None

    def authenticateCredentials(self, credentials):
        if credentials['extractor'] != self.getId():
            return (None, None)

        username = credentials['login']
        return (username, username)

    security.declarePrivate('challenge')
    def challenge(self, request, response, **kw):
        """ Challenge the user for credentials. """
        # Remove current credentials.
        session = self.REQUEST.SESSION
        session[self.session_var] = None

        # protect against endless cas->zope->cas->zope->cas->you see?...
        if request.has_key('ticket'):
            return 0

        # Redirect to CAS login URL.
        url = self.getLoginURL()
        if not url:
            return 0

        service = self.getService(request)
        #del response.headers['WWW-Authenticate']
        if self.gateway_mode:
            response.redirect('%s?gateway=true&service=%s' % (url, service), lock=1)
            return 1
        else:
            response.redirect('%s?service=%s' % (url, service), lock=1)
            return 1

        # Fall through to the standard unauthorized() call.
        return 0


    security.declarePrivate('resetCredentials')
    def resetCredentials(self, request, response):
        """ Clears credentials and redirects to CAS logout page"""
        session = self.REQUEST.SESSION
        session[self.session_var] = None
        if self.logout_url:
            self.REQUEST.RESPONSE.redirect(self.logout_url)


    security.declarePrivate('getLoginURL')
    def getLoginURL(self):
        """ Where to send people for logging in """
        return self.login_url


    def getService(self, request):
        """extract urlencoded service URL from REQUEST and remove the ticket from
        GET parameters
        This function handles GET parameters
        """
        service = request['URL']

        # remove ticket parameter(s)
        query_string = request.get('QUERY_STRING', "")
        ticket_idx = query_string.find('ticket=')
        if ticket_idx > 1:
            # ticket is after some other parameters that we preserve
            # we also remove the '&' char
            query_string =  query_string[:ticket_idx - 1]
        elif ticket_idx == 0:
            # ticket was the only parameter
            query_string = ""

        # add filtered QUERY_STRING to service
        if query_string:
            service = "%s?%s" % (service, query_string)

        return urllib.quote(service)


classImplements(CASAuthHelper,
                IExtractionPlugin,
                IChallengePlugin,
                ICredentialsResetPlugin,
                IAuthenticationPlugin)

InitializeClass(CASAuthHelper)

