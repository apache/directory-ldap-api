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


import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import javax.inject.Inject;

import org.apache.directory.api.ldap.codec.protocol.mina.LdapProtocolCodecFactory;
import org.apache.directory.api.ldap.codec.protocol.mina.LdapProtocolDecoder;
import org.apache.directory.api.ldap.codec.protocol.mina.LdapProtocolEncoder;
import org.junit.Test;
import org.osgi.framework.ServiceReference;


public class ApiLdapNetMinaOsgiTest extends ApiOsgiTestBase
{

    @Inject
    LdapProtocolCodecFactory ldapProtocolCodecFactory;


    @Override
    protected String getBundleName()
    {
        return "org.apache.directory.api.ldap.net.mina";
    }


    @Override
    protected void useBundleClasses() throws Exception
    {
        new LdapProtocolDecoder();
        new LdapProtocolEncoder();
    }


    @Test
    public void testInjectLdapProtocolCodecFactory()
    {
        assertNotNull( ldapProtocolCodecFactory );
    }


    @Test
    public void testLookupLdapProtocolCodecFactory()
    {
        ServiceReference<LdapProtocolCodecFactory> serviceReference = context.getServiceReference( LdapProtocolCodecFactory.class );
        Object service = context.getService( serviceReference );
        assertNotNull( service );
        assertTrue( service instanceof LdapProtocolCodecFactory );
    }

}
