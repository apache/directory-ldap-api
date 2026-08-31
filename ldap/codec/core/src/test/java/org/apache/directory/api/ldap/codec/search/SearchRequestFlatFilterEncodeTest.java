/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.directory.api.ldap.codec.search;


import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.codec.osgi.AbstractCodecServiceTest;
import org.apache.directory.api.ldap.model.filter.FilterParser;
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests that encoding a filter whose element count derives from untrusted
 * input uses bounded stack: a completely flat filter with tens of thousands
 * of siblings must encode without a StackOverflowError (the stack depth must
 * not grow with the number of children of a connector node).
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class SearchRequestFlatFilterEncodeTest extends AbstractCodecServiceTest
{
    /** Enough siblings to exhaust a default thread stack if encoding recursed per sibling */
    private static final int SIBLINGS = 50_000;


    @Test
    public void testEncodeFlatFilterWithManySiblings() throws Exception
    {
        StringBuilder filter = new StringBuilder( "(|" );

        for ( int i = 0; i < SIBLINGS; i++ )
        {
            filter.append( "(cn=a" ).append( i ).append( ')' );
        }

        filter.append( ')' );

        SearchRequest searchRequest = new SearchRequestImpl();
        searchRequest.setMessageId( 1 );
        searchRequest.setBase( new Dn( "dc=example,dc=com" ) );
        searchRequest.setScope( SearchScope.SUBTREE );
        searchRequest.setDerefAliases( AliasDerefMode.NEVER_DEREF_ALIASES );
        searchRequest.setFilter( FilterParser.parse( filter.toString() ) );

        Asn1Buffer buffer = new Asn1Buffer();

        // Must not throw StackOverflowError
        assertNotNull( LdapEncoder.encodeMessage( buffer, codec, searchRequest ) );
    }
}
