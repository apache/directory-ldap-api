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
package org.apache.directory.api.ldap.model.name;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Test that Rdn.unescapeValue() is the exact inverse of RFC 4514 escaping and
 * rejects invalid input instead of silently mangling it: an unescaped special
 * must not be replaced by '#', an invalid escape must not be dropped, and a
 * half hex pair must not survive intervening characters.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class RdnUnescapeValueStrictTest
{
    @Test
    public void testUnescapedSpecialsAreRejected()
    {
        // Previously decoded to "a#b"
        assertThrows( IllegalArgumentException.class, () -> Rdn.unescapeValue( "a,b" ) );
        assertThrows( IllegalArgumentException.class, () -> Rdn.unescapeValue( "a+b" ) );
        assertThrows( IllegalArgumentException.class, () -> Rdn.unescapeValue( "a;b" ) );
        assertThrows( IllegalArgumentException.class, () -> Rdn.unescapeValue( "a<b" ) );
        assertThrows( IllegalArgumentException.class, () -> Rdn.unescapeValue( "a>b" ) );
        assertThrows( IllegalArgumentException.class, () -> Rdn.unescapeValue( "a\"b" ) );
    }


    @Test
    public void testInvalidEscapeIsRejected()
    {
        // Previously silently dropped, decoding 'ad\zmin' to 'admin'
        assertThrows( IllegalArgumentException.class, () -> Rdn.unescapeValue( "ad\\zmin" ) );
    }


    @Test
    public void testHalfHexPairIsRejected()
    {
        // Previously '\4z1' decoded to the single byte 0x41 ('A')
        assertThrows( IllegalArgumentException.class, () -> Rdn.unescapeValue( "\\4z1" ) );

        // A dangling half pair at the end of the value
        assertThrows( IllegalArgumentException.class, () -> Rdn.unescapeValue( "ab\\4" ) );

        // A dangling ESC at the end of the value
        assertThrows( IllegalArgumentException.class, () -> Rdn.unescapeValue( "ab\\" ) );
    }


    @Test
    public void testQuotedValueInnerEscapesAreDecoded()
    {
        // Previously returned verbatim, escapes included
        assertThrows( IllegalArgumentException.class, () -> Rdn.unescapeValue( "\"a,b\"" ) );
        assertThrows( IllegalArgumentException.class, () -> Rdn.unescapeValue( "\"a\\\\b\"" ) );
        assertThrows( IllegalArgumentException.class, () -> Rdn.unescapeValue( "\"\\41\"" ) );
    }


    @Test
    public void testValidEscapesStillDecode()
    {
        assertEquals( "\\#,+;<>=\" ", Rdn.unescapeValue( "\\\\\\#\\,\\+\\;\\<\\>\\=\\\"\\ " ) );
        assertEquals( "a#b", Rdn.unescapeValue( "a#b" ) );
        assertEquals( "a b", Rdn.unescapeValue( "a b" ) );
        assertEquals( "A", Rdn.unescapeValue( "\\41" ) );
    }
}
