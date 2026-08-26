/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.api.util;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.text.ParseException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests that the ParserUtil primitives report truncated input with a clean
 * ParseException instead of escaping with a StringIndexOutOfBoundsException,
 * which callers like ACIItemParser and SubtreeSpecificationParser (which catch
 * ParseException only) would propagate to the validating thread.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class ParserUtilTruncatedInputTest
{
    private Position position( String str )
    {
        Position pos = new Position( str );
        pos.length = str.length();

        return pos;
    }


    /**
     * parseOid on input ending where the OID should start (e.g. an ACIItem or
     * refinement truncated after 'item:') must throw a ParseException.
     */
    @Test
    public void testParseOidAtEndOfInput()
    {
        assertThrows( ParseException.class, () -> ParserUtil.parseOid( "", position( "" ) ) );
        assertThrows( ParseException.class, () -> ParserUtil.parseOid( "   ", position( "   " ) ) );
    }


    /**
     * parseDescr at end of input must throw a ParseException, and must not
     * dereference past the end of the string while building the error message.
     */
    @Test
    public void testParseDescrAtEndOfInput()
    {
        assertThrows( ParseException.class, () -> ParserUtil.parseDescr( "", position( "" ) ) );
    }


    /**
     * parseInteger at end of input, or on a non-digit, must throw a ParseException.
     */
    @Test
    public void testParseIntegerAtEndOfInput()
    {
        assertThrows( ParseException.class, () -> ParserUtil.parseInteger( "", position( "" ) ) );
        assertThrows( ParseException.class, () -> ParserUtil.parseInteger( "}", position( "}" ) ) );
    }


    /**
     * Valid inputs must still parse.
     */
    @Test
    public void testValidInputsStillParse() throws ParseException
    {
        assertEquals( "2.5.6.0", ParserUtil.parseOid( "2.5.6.0", position( "2.5.6.0" ) ) );
        assertEquals( "person", ParserUtil.parseOid( " person", position( " person" ) ) );
        assertEquals( "cn", ParserUtil.parseDescr( "cn", position( "cn" ) ) );
        assertEquals( 42, ParserUtil.parseInteger( "42", position( "42" ) ) );
        assertEquals( 0, ParserUtil.parseInteger( "0}", position( "0}" ) ) );
    }
}
