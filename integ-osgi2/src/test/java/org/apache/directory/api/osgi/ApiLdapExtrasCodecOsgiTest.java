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

import org.apache.directory.api.ldap.codec.api.CodecControl;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.ppolicy.PasswordPolicy;
import org.apache.directory.api.ldap.extras.controls.ppolicy_impl.PasswordPolicyDecorator;
import org.apache.directory.api.ldap.extras.extended.ads_impl.startTls.StartTlsRequestDecorator;
import org.apache.directory.api.ldap.extras.extended.startTls.StartTlsRequest;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;


public class ApiLdapExtrasCodecOsgiTest extends ApiOsgiTestBase
{

    @Inject
    LdapApiService ldapApiService;


    @Override
    protected String getBundleName()
    {
        return "org.apache.directory.api.ldap.extras.codec";
    }


    @Override
    protected void useBundleClasses() throws Exception
    {
        CodecControl<? extends Control> control = ldapApiService.newControl( PasswordPolicy.OID );
        assertNotNull( control );
        assertTrue( control instanceof PasswordPolicyDecorator );

        ExtendedRequest extendedRequest = ldapApiService.newExtendedRequest( StartTlsRequest.EXTENSION_OID, null );
        assertNotNull( extendedRequest );
        assertTrue( extendedRequest instanceof StartTlsRequestDecorator );
    }

}
