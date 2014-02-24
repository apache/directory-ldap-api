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


import java.text.Format;
import java.text.MessageFormat;


/**
 * An encoder for LDAP filters.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class FilterEncoder
{
    private static final String[] EMPTY = new String[0];


    /**
     * Formats a filter and handles encoding of special characters in the value arguments using the
     * &lt;valueencoding&gt; rule as described in <a href="http://www.ietf.org/rfc/rfc4515.txt">RFC 4515</a>.
     * <p>
     * Example of filter template format: <code>(&(cn={0})(uid={1}))</code>
     * 
     * @param filterTemplate the filter with placeholders
     * @param values the values to encode and substitute
     * @return the formatted filter with escaped values
     * @throws IllegalArgumentException if the number of values does not match the number of placeholders in the template
     */
    public static String format( String filterTemplate, String... values ) throws IllegalArgumentException
    {
        if ( values == null )
        {
            values = EMPTY;
        }

        MessageFormat mf = new MessageFormat( filterTemplate );

        // check element count and argument count
        Format[] formats = mf.getFormatsByArgumentIndex();
        if ( formats.length != values.length )
        {
            // TODO: I18n
            String msg = "Filter template {0} has {1} placeholders but {2} arguments provided.";
            throw new IllegalArgumentException( MessageFormat.format( msg, filterTemplate, formats.length,
                values.length ) );
        }

        // encode arguments
        for ( int i = 0; i < values.length; i++ )
        {
            values[i] = encodeFilterValue( values[i] );
        }

        // format the filter
        String format = mf.format( values );
        return format;
    }


    /**
     * Handles encoding of special characters in LDAP search filter assertion values using the
     * &lt;valueencoding&gt; rule as described in <a href="http://www.ietf.org/rfc/rfc4515.txt">RFC 4515</a>.
     *
     * @param value Right hand side of "attrId=value" assertion occurring in an LDAP search filter.
     * @return Escaped version of <code>value</code>
     */
    public static String encodeFilterValue( String value )
    {
        StringBuilder sb = null;

        for ( int i = 0; i < value.length(); i++ )
        {
            char ch = value.charAt( i );
            String replace = null;

            switch ( ch )
            {
                case '*':
                    replace = "\\2A";
                    break;

                case '(':
                    replace = "\\28";
                    break;

                case ')':
                    replace = "\\29";
                    break;

                case '\\':
                    replace = "\\5C";
                    break;

                case '\0':
                    replace = "\\00";
                    break;
            }

            if ( replace != null )
            {
                if ( sb == null )
                {
                    sb = new StringBuilder( value.length() * 2 );
                    sb.append( value.substring( 0, i ) );
                }
                sb.append( replace );
            }
            else if ( sb != null )
            {
                sb.append( ch );
            }
        }

        return ( sb == null ? value : sb.toString() );
    }
}
