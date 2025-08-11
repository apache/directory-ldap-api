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

import java.util.HashMap;

import org.apache.commons.text.translate.CharSequenceTranslator;
import org.apache.commons.text.translate.LookupTranslator;


/**
 * Create unescapers and escapers for the RFC 4517 Postal Address syntax.
 *
 * <pre>
 * PostalAddress = line *( DOLLAR line )
 * line          = 1*line-char
 * line-char     = %x00-23
 *                 / (%x5C "24")  ; escaped "$"
 *                 / %x25-5B
 *                 / (%x5C "5C")  ; escaped "\"
 *                 / %x5D-7F
 *                 / UTFMB
 * </pre>
 */
public final class PostalAddress
{
    /**
     * Create an unescaper that uses the specified line separator.
     *
     * @param separator the separator to output between address lines
     * @return a commons-text translator object for unescaping
     */
    public static CharSequenceTranslator createUnescaper( String separator )
    {
        return new LookupTranslator(
            new HashMap<CharSequence, CharSequence>()
            {{
                put( "$", separator );
                put( "\\24", "$" );
                put( "\\5C", "\\" );
                put( "\\5c", "\\" );
            }}
        );
    }

    /**
     * Create an escaper that uses the specified line separator.
     *
     * @param separator the separator used between address lines
     * @return a commons-text translator object for escaping
     */
    public static CharSequenceTranslator createEscaper( String separator )
    {
        return new LookupTranslator(
            new HashMap<CharSequence, CharSequence>()
            {{
                put( "\\", "\\5C" );
                put( "$", "\\24" );
                put( separator, "$" );
            }}
        );
    }

    private PostalAddress()
    {
    }
}
