/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.api.osgi;


import org.apache.directory.api.ldap.aci.ACIItemChecker;
import org.apache.directory.api.ldap.aci.ACIItemParser;
import org.apache.directory.api.ldap.aci.GrantAndDenial;
import org.apache.directory.api.ldap.aci.MicroOperation;
import org.apache.directory.api.ldap.aci.ProtectedItem;
import org.apache.directory.api.ldap.aci.UserClass;


public class ApiLdapExtrasAciOsgiTest extends ApiOsgiTestBase
{

    @Override
    protected String getBundleName()
    {
        return "org.apache.directory.api.ldap.extras.aci";
    }


    @Override
    protected void useBundleClasses() throws Exception
    {
        GrantAndDenial.GRANT_BROWSE.toString();
        MicroOperation.BROWSE.getName();
        UserClass.THIS_ENTRY.toString();
        ProtectedItem.ENTRY.toString();

        new ACIItemChecker( null ).parse( "" );
        new ACIItemParser( null ).parse( "" );

        String spec = "{ identificationTag \"test\", precedence 14, authenticationLevel simple, "
            + "itemOrUserFirst userFirst: { userClasses { allUsers }, userPermissions { { "
            + "precedence 1, protectedItems { attributeType { userPassword } }, grantsAndDenials "
            + "{ denyRead, denyReturnDN, denyBrowse } }, { precedence 2, protectedItems "
            + "{ entry, allUserAttributeTypesAndValues }, grantsAndDenials "
            + "{ grantReturnDN, grantRead, grantBrowse } } } } }";
        new ACIItemParser( null ).parse( spec );
    }

}
