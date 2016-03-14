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


import static org.junit.Assert.assertEquals;

import javax.naming.Name;

import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.util.JndiUtils;
import org.apache.directory.api.ldap.util.tree.DnNode;


public class ApiLdapExtrasUtilOsgiTest extends ApiOsgiTestBase
{

    @Override
    protected String getBundleName()
    {
        return "org.apache.directory.api.ldap.extras.util";
    }


    @Override
    protected void useBundleClasses() throws Exception
    {
        Dn dn = new Dn( "cn=foo" );
        Name name = JndiUtils.toName( dn );
        assertEquals( name.toString(), dn.toString() );
        new DnNode<Object>().add( dn ).getParent();
    }

}
