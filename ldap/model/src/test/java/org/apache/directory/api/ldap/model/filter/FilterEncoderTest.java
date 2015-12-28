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
package org.apache.directory.api.ldap.model.filter;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;


/**
 * Tests for {@link FilterEncoder}.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class FilterEncoderTest
{

    private static final String[] ZERO = new String[0];
    private static final String[] ONE = new String[]
        { "foo" };
    private static final String[] TWO = new String[]
        { "foo", "bar" };
    private static final String[] SPECIAL_CHARS = new String[]
        { "(\\*\0)" };


    @Test
    public void testFormatWithNoPlaceholdersAndCorrectArgumentCount()
    {
        assertEquals( "(cn=foo)", FilterEncoder.format( "(cn=foo)", (String[])null ) );
        assertEquals( "(cn=foo)", FilterEncoder.format( "(cn=foo)", ZERO ) );
    }


    @Test(expected = IllegalArgumentException.class)
    public void testFormatWithNoPlaceholdersAndTooManyArguments()
    {
        FilterEncoder.format( "(cn=foo)", ONE );
    }


    @Test(expected = IllegalArgumentException.class)
    public void testFormatWithPlaceholdersAndTooFewArguments()
    {
        FilterEncoder.format( "(cn={0})", ZERO );
    }


    @Test
    public void testFormatWithPlaceholdersAndCorrectArgumentCount()
    {
        assertEquals( "(cn=foo)", FilterEncoder.format( "(cn={0})", ONE ) );
        assertEquals( "(&(cn=foo)(uid=bar))", FilterEncoder.format( "(&(cn={0})(uid={1}))", TWO ) );
    }


    @Test(expected = IllegalArgumentException.class)
    public void testFormatWithPlaceholdersAndTooManyArguments()
    {
        FilterEncoder.format( "(cn={0})", TWO );
    }


    @Test
    public void testFormatWithPlaceholdersAndSpecialChars()
    {
        assertEquals( "(cn=\\28\\5C\\2A\\00\\29)", FilterEncoder.format( "(cn={0})", SPECIAL_CHARS ) );
    }


    @Test
    public void testExceptionMessage()
    {
        try
        {
            FilterEncoder.format( "(&(cn={0})(uid={1}))", ONE );
            fail( "IllegalArgumentException expected" );
        }
        catch ( IllegalArgumentException e )
        {
            String message = e.getMessage();
            assertTrue( message.contains( " (&(cn={0})(uid={1})) " ) );
            assertTrue( message.contains( " 2 " ) );
            assertTrue( message.contains( " 1 " ) );
        }
    }


    @Test
    public void testEncodeFilterValue()
    {
        assertEquals( "1234567890", FilterEncoder.encodeFilterValue( "1234567890" ) );
        assertEquals( "\\28", FilterEncoder.encodeFilterValue( "(" ) );
        assertEquals( "\\29", FilterEncoder.encodeFilterValue( ")" ) );
        assertEquals( "\\2A", FilterEncoder.encodeFilterValue( "*" ) );
        assertEquals( "\\5C", FilterEncoder.encodeFilterValue( "\\" ) );
        assertEquals( "\\00", FilterEncoder.encodeFilterValue( "\0" ) );
        assertEquals( "\\28\\2A\\29", FilterEncoder.encodeFilterValue( "(*)" ) );
        assertEquals( "a test \\2A \\5Cend", FilterEncoder.encodeFilterValue( "a test \\2A \\end" ) );
    }

}
