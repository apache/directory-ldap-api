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

package org.apache.directory.api.dsmlv2;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.directory.api.dsmlv2.batchRequest.BatchRequestTest;
import org.apache.directory.api.dsmlv2.batchResponse.BatchResponseTest;
import org.apache.directory.api.dsmlv2.request.BatchRequestDsml;
import org.apache.directory.api.dsmlv2.response.BatchResponseDsml;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests for ParserUtils.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT)
public class ParserUtilsTest extends AbstractTest
{

    private static final Pattern NEW_LINE_PATTERN = Pattern.compile( "\n", Pattern.DOTALL );
    private static final Pattern INDENTION_PATTERN = Pattern.compile( "   ", Pattern.DOTALL );


    /**
     * Test for DIRAPI-238: DSML pretty print does not work, prints error.
     * 
     * Indirect test of ParserUtils.styleDocument() via BatchRequestDsml.toDsml().
     * 
     * @throws Exception If the test failed
     */
    @Test
    public void testStyleDocumentWithBatchRequest() throws Exception
    {
        Dsmlv2Parser parser = newParser();
        parser.setInput( BatchRequestTest.class.getResource( "request_with_2_AddRequest.xml" ).openStream(), "UTF-8" );
        parser.parse();
        BatchRequestDsml batchRequest = parser.getBatchRequest();

        String dsml = batchRequest.toDsml();
        assertNotNull( dsml );

        assertEquals( 20, countNewlines( dsml ), "Pretty printed DSML should contain newlines" );
        assertEquals( 38, countIndention( dsml ), "Pretty printed DSML should contain indention" );
    }


    /**
     * Test for DIRAPI-238: DSML pretty print does not work, prints error.
     * 
     * Indirect test of ParserUtils.styleDocument() via BatchResponseDsml.toDsml() 
     * 
     * @throws Exception If the test failed
     */
    @Test
    public void testStyleDocumentWithBatchResponse() throws Exception
    {
        Dsmlv2ResponseParser parser = new Dsmlv2ResponseParser( getCodec() );
        parser.setInput( BatchResponseTest.class.getResource( "response_with_2_SearchResponse.xml" ).openStream(),
            "UTF-8" );
        parser.parse();
        BatchResponseDsml batchResponse = parser.getBatchResponse();

        String dsml = batchResponse.toDsml();
        assertNotNull( dsml );

        assertEquals( 12, countNewlines( dsml ), "Pretty printed DSML should contain newlines" );
        assertEquals( 18, countIndention( dsml ), "Pretty printed DSML should contain indention" );
    }


    private int countNewlines( String dsml )
    {
        return count( NEW_LINE_PATTERN, dsml );
    }


    private int countIndention( String dsml )
    {
        return count( INDENTION_PATTERN, dsml );
    }


    private int count( Pattern p, String dsml )
    {
        Matcher matcher = p.matcher( dsml );
        int count = 0;
        while ( matcher.find() )
        {
            count++;
        }
        return count;
    }

}
