# -*- coding: ISO-8859-15 -*-
# (C) Copyright 2005 Nuxeo SARL <http://nuxeo.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# $Id$

from AccessControl.Permissions import manage_users as ManageUsers
from Products.PluggableAuthService.PluggableAuthService import registerMultiPlugin, MultiPlugins
import CASAuthHelper

mt = CASAuthHelper.CASAuthHelper.meta_type

if mt not in MultiPlugins:
    registerMultiPlugin(mt)
 
def initialize(context):

    context.registerClass(CASAuthHelper.CASAuthHelper, 
                          permission=ManageUsers,
                          constructors=(CASAuthHelper.addCASAuthHelperForm,
                                        CASAuthHelper.addCASAuthHelper, ),
                          visibility=None,
                          icon='zmi/CASAuthHelper.gif'
                         )
