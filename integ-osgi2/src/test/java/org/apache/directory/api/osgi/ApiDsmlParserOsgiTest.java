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


import org.apache.directory.api.dsmlv2.ParserUtils;
import org.apache.directory.api.dsmlv2.request.AddRequestDsml;
import org.apache.directory.api.dsmlv2.request.Dsmlv2Grammar;
import org.apache.directory.api.dsmlv2.request.SearchRequestDsml;
import org.apache.directory.api.dsmlv2.response.LdapResultDsml;
import org.apache.directory.api.dsmlv2.response.SearchResponse;
import org.apache.directory.api.dsmlv2.response.SearchResultDoneDsml;
import org.apache.directory.api.dsmlv2.response.SearchResultEntryDsml;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.message.AddRequestImpl;
import org.apache.directory.api.ldap.model.message.LdapResultImpl;
import org.apache.directory.api.ldap.model.message.ReferralImpl;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.url.LdapUrl;
import org.dom4j.tree.BaseElement;


public class ApiDsmlParserOsgiTest extends ApiOsgiTestBase
{

    @Override
    protected String getBundleName()
    {
        return "org.apache.directory.api.dsmlv2.parser";
    }


    @Override
    protected void useBundleClasses() throws Exception
    {
        new Dsmlv2Grammar();

        new AddRequestDsml( null );
        new SearchRequestDsml( null );

        ParserUtils.base64Encode( "abc" );
        new Dn( "cn=foo" );
        new LdapUrl( "ldap://example.com/" );
        ResultCodeEnum.TOO_LATE.getMessage();
        ParserUtils.needsBase64Encoding( null );
        ParserUtils.parseAndVerifyRequestID( "5", null );
        new BaseElement( "foo" );
        context.getService( context.getServiceReference( LdapApiService.class.getName() ) );
        new AddRequestImpl();
        new ReferralImpl();
        new LdapResultImpl();

        new SearchResponse();
        new LdapResultDsml( null, null, null );
        new SearchResultEntryDsml( null );
        new SearchResultDoneDsml( null );
    }

}
