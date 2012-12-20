/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.directory.api.dsmlv2.soap;


import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.apache.directory.api.dsmlv2.Dsmlv2Parser;
import org.apache.directory.api.dsmlv2.request.BatchRequestDsml;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.junit.Test;


/**
 * Class which tests the parsing of DSML documents embedded in a SOAP envelope.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SoapDsmlParsingTest
{

    @Test
    public void testParsingRequestsOneByOne() throws Exception
    {

        Dsmlv2Parser parser = new Dsmlv2Parser( false );

        parser.setInput( SoapDsmlParsingTest.class.getResource( "soap-dsml-multiple-operation-requests.xml" )
            .openStream(),
            "UTF-8" );

        parser.parseBatchRequest();

        BatchRequestDsml batchReq = parser.getBatchRequest();

        assertNotNull( batchReq );
        assertFalse( batchReq.isStoringRequests() );

        assertTrue( batchReq.getRequests().isEmpty() );

        SearchRequest searchRequest = ( SearchRequest ) parser.getNextRequest();

        assertTrue( searchRequest.getTypesOnly() );

        // assert again that the batch request object is not storing requests
        assertTrue( batchReq.getRequests().isEmpty() );

        searchRequest = ( SearchRequest ) parser.getNextRequest();

        assertFalse( searchRequest.getTypesOnly() );

        assertNull( parser.getNextRequest() );

        // assert again that the batch request object is not storing requests
        assertTrue( batchReq.getRequests().isEmpty() );

        assertNotNull( batchReq.getCurrentRequest() );
    }


    /**
     * Test parsing of a request without a SOAP header
     */
    @Test
    public void testBatchRequestWithoutSoapHeader()
    {
        Dsmlv2Parser parser = null;
        try
        {
            parser = new Dsmlv2Parser();

            parser.setInput( SoapDsmlParsingTest.class.getResource( "soap-dsml-req-without-header.xml" ).openStream(),
                "UTF-8" );

            SearchRequest searchRequest = ( SearchRequest ) parser.getNextRequest();

            assertTrue( searchRequest.getTypesOnly() );
        }
        catch ( Exception e )
        {
            fail( e.getMessage() );
        }

    }


    /**
     * Test parsing of a request *with* a SOAP header
     */
    @Test
    public void testBatchRequestWithSoapHeader()
    {
        Dsmlv2Parser parser = null;
        try
        {
            parser = new Dsmlv2Parser();

            parser.setInput( SoapDsmlParsingTest.class.getResource( "soap-dsml-req-with-header.xml" ).openStream(),
                "UTF-8" );

            parser.parse();
        }
        catch ( Exception e )
        {
            fail( e.getMessage() );
        }

        SearchRequest searchRequest = ( SearchRequest ) parser.getBatchRequest().getCurrentRequest();

        assertTrue( searchRequest.getTypesOnly() );
    }

}
