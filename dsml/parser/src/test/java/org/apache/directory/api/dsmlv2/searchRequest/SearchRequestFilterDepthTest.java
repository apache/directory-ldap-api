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

package org.apache.directory.api.dsmlv2.searchRequest;


import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.apache.directory.api.dsmlv2.AbstractTest;
import org.apache.directory.api.dsmlv2.Dsmlv2Parser;
import org.apache.directory.api.dsmlv2.request.SearchRequestDsml;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.xmlpull.v1.XmlPullParserException;


/**
 * Tests that the depth of a searchRequest filter, which is fully driven by
 * the incoming DSML document, is bounded : a deeply nested filter must be
 * rejected with an XmlPullParserException instead of triggering a
 * StackOverflowError.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class SearchRequestFilterDepthTest extends AbstractTest
{
    /**
     * Build a batchRequest whose searchRequest filter is <code>depth</code>
     * nested &lt;not&gt; elements around a present filter.
     */
    private String buildRequestWithNestedNot( int depth )
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "<batchRequest xmlns=\"urn:oasis:names:tc:DSML:2.0:core\">" );
        sb.append( "<searchRequest dn=\"ou=marketing,dc=example,dc=com\"" );
        sb.append( " scope=\"baseObject\" derefAliases=\"neverDerefAliases\">" );
        sb.append( "<filter>" );

        for ( int i = 0; i < depth; i++ )
        {
            sb.append( "<not>" );
        }

        sb.append( "<present name=\"objectclass\"/>" );

        for ( int i = 0; i < depth; i++ )
        {
            sb.append( "</not>" );
        }

        sb.append( "</filter>" );
        sb.append( "</searchRequest>" );
        sb.append( "</batchRequest>" );

        return sb.toString();
    }


    /**
     * A filter nested deeper than the default limit must be rejected with an
     * XmlPullParserException, not a StackOverflowError.
     */
    @Test
    public void testDeeplyNestedFilterIsRejected() throws Exception
    {
        Dsmlv2Parser parser = newParser();
        parser.setInput( buildRequestWithNestedNot( SearchRequestDsml.DEFAULT_MAX_FILTER_DEPTH + 10 ) );

        assertThrows( XmlPullParserException.class, parser::parse );
    }


    /**
     * A reasonably nested filter must still parse fine.
     */
    @Test
    public void testReasonablyNestedFilterIsAccepted() throws Exception
    {
        Dsmlv2Parser parser = newParser();
        parser.setInput( buildRequestWithNestedNot( 10 ) );

        parser.parse();

        SearchRequest searchRequest = ( SearchRequest ) parser.getBatchRequest().getCurrentRequest();

        assertNotNull( searchRequest.getFilter() );
    }
}
