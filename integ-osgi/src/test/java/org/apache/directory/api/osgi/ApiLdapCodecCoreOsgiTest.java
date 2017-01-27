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


import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import javax.inject.Inject;

import org.apache.directory.api.ldap.codec.LdapStatesEnum;
import org.apache.directory.api.ldap.codec.actions.addRequest.InitAddRequest;
import org.apache.directory.api.ldap.codec.actions.addResponse.InitAddResponse;
import org.apache.directory.api.ldap.codec.actions.bindRequest.InitBindRequest;
import org.apache.directory.api.ldap.codec.actions.bindResponse.InitBindResponse;
import org.apache.directory.api.ldap.codec.actions.searchRequest.InitSearchRequest;
import org.apache.directory.api.ldap.codec.actions.searchResultDone.InitSearchResultDone;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapApiServiceFactory;
import org.apache.directory.api.ldap.codec.decorators.SearchRequestDecorator;
import org.apache.directory.api.ldap.codec.search.AndFilter;
import org.apache.directory.api.ldap.codec.search.SubstringFilter;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;
import org.junit.Test;
import org.osgi.framework.ServiceReference;


public class ApiLdapCodecCoreOsgiTest extends ApiOsgiTestBase
{

    @Inject
    LdapApiService ldapApiService;


    @Override
    protected String getBundleName()
    {
        return "org.apache.directory.api.ldap.codec.core";
    }


    @Override
    protected void useBundleClasses() throws Exception
    {
        LdapStatesEnum.END_STATE.isEndState();

        new InitBindRequest();
        new InitBindResponse();
        new InitAddRequest();
        new InitAddResponse();
        new InitSearchRequest();
        new InitSearchResultDone();

        new AndFilter();
        new SubstringFilter();

        SearchRequest decoratedMessage = new SearchRequestImpl();
        new SearchRequestDecorator( ldapApiService, decoratedMessage );
    }


    @Test
    public void testInjectLdapApiService()
    {
        assertNotNull( ldapApiService );
    }


    @Test
    public void testLookupLdapApiService()
    {
        ServiceReference<LdapApiService> serviceReference = context.getServiceReference( LdapApiService.class );
        Object service = context.getService( serviceReference );
        assertNotNull( service );
        assertTrue( service instanceof LdapApiService );
    }


    @Test
    public void testLdapApiServiceFactoryIsInitializedByOsgi()
    {
        assertTrue( LdapApiServiceFactory.isInitialized() );
        assertFalse( LdapApiServiceFactory.isUsingStandaloneImplementation() );
        
        LdapApiService ldapApiService = LdapApiServiceFactory.getSingleton();
        assertNotNull( ldapApiService );
        assertNotNull( ldapApiService.getProtocolCodecFactory() );
        
        assertTrue( ldapApiService.isControlRegistered( SortRequest.OID ) );
    }
}
