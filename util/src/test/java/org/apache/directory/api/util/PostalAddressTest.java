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
package org.apache.directory.api.util;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.apache.commons.text.translate.CharSequenceTranslator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests the PostalAddress class methods.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class PostalAddressTest
{
    @Test
    public void testTrivial()
    {
        assertEquals( "abc", PostalAddress.createUnescaper( "!" ).translate( "abc" ) );
        assertEquals( "abc", PostalAddress.createEscaper( "!" ).translate( "abc" ) );
    }


    @Test
    public void testEscaped()
    {
        CharSequenceTranslator unescaper = PostalAddress.createUnescaper( "!" );
        assertEquals( "!", unescaper.translate( "$" ) );
        assertEquals( "$", unescaper.translate( "\\24" ) );
        assertEquals( "\\", unescaper.translate( "\\5C" ) );
        assertEquals( "\\", unescaper.translate( "\\5c" ) );
        assertEquals( "\\5C", unescaper.translate( "\\5c5C" ) );
        assertEquals( "\\5c", unescaper.translate( "\\5C5c" ) );

        CharSequenceTranslator escaper = PostalAddress.createEscaper( "!" );
        assertEquals( "$", escaper.translate( "!" ) );
        assertEquals( "\\24", escaper.translate( "$" ) );
        assertEquals( "\\5C", escaper.translate( "\\" ) );
    }


    @Test
    public void testRfcExamples()
    {
        CharSequenceTranslator unescaper = PostalAddress.createUnescaper( "\n" );
        assertEquals( "1234 Main St.\nAnytown, CA 12345\nUSA",
            unescaper.translate( "1234 Main St.$Anytown, CA 12345$USA" ) );
        assertEquals( "$1,000,000 Sweepstakes\nPO Box 1000000\nAnytown, CA 12345\nUSA",
            unescaper.translate( "\\241,000,000 Sweepstakes$PO Box 1000000$Anytown, CA 12345$USA" ) );

        CharSequenceTranslator escaper = PostalAddress.createEscaper( "\n" );
        assertEquals( "1234 Main St.$Anytown, CA 12345$USA",
            escaper.translate( "1234 Main St.\nAnytown, CA 12345\nUSA" ) );
        assertEquals( "\\241,000,000 Sweepstakes$PO Box 1000000$Anytown, CA 12345$USA",
            escaper.translate( "$1,000,000 Sweepstakes\nPO Box 1000000\nAnytown, CA 12345\nUSA" ) );
    }
}
