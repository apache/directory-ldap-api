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
package org.apache.directory.api.ldap.model.schema.syntaxCheckers;


import java.util.regex.Pattern;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.util.Strings;


/**
 * A SyntaxChecker which verifies that a value is a UTC time
 * according to RFC 4517.
 * <p>
 * From RFC 4517 :
 * <pre>
 * UTCTime         = year month day hour minute [ second ] [ u-time-zone ]
 * u-time-zone     = %x5A          ; "Z" | u-differential
 * u-differential  = ( MINUS | PLUS ) hour minute
 *
 * year    = 2(%x30-39)            ; "00" to "99"
 * month   = ( %x30 %x31-39 )      ; "01" (January) to "09"
 *           | ( %x31 %x30-32 )    ; "10" to "12"
 * day     = ( %x30 %x31-39 )      ; "01" to "09"
 *           | ( %x31-32 %x30-39 ) ; "10" to "29"
 *           | ( %x33 %x30-31 )    ; "30" to "31"
 * hour    = ( %x30-31 %x30-39 ) 
 *           | ( %x32 %x30-33 )    ; "00" to "23"
 * minute  = %x30-35 %x30-39       ; "00" to "59"
 *
 * second  = ( %x30-35 %x30-39 )   ; "00" to "59"
 *
 * g-time-zone = %x5A              ; "Z"
 *               | g-differential
 * g-differential = ( MINUS / PLUS ) hour [ minute ]
 * MINUS   = %x2D  ; minus sign ("-")
 * 
 * From RFC 4512 :
 * PLUS    = %x2B ; plus sign ("+")
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class UtcTimeSyntaxChecker extends SyntaxChecker
{
    /** The GeneralizedDate pattern matching */
    private static final String UTC_TIME_PATTERN =
        // year : 00 to 99
        "^\\d{2}"
            // month : 01 to 12
            + "(0[1-9]|1[0-2])"
            // day : 01 to 31
            + "(0[1-9]|[12]\\d|3[01])"
            // hour: 00 to 23
            + "([01]\\d|2[0-3])"
            // minute : 00 to 59
            + "([0-5]\\d)"
            + "("
            // optional second : 00 to 59
            + "([0-5]\\d)?"
            // optional time-zone
            + "(Z|([+-]([01]\\d|2[0-3])[0-5]\\d))?"
            + ")$";

    // The regexp pattern, java.util.regex.Pattern is immutable so only one instance is needed.
    private static final Pattern DATE_PATTERN = Pattern.compile( UTC_TIME_PATTERN );
    
    /**
     * A static instance of UtcTimeSyntaxChecker
     */
    public static final UtcTimeSyntaxChecker INSTANCE = new UtcTimeSyntaxChecker( SchemaConstants.UTC_TIME_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<UtcTimeSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.UTC_TIME_SYNTAX );
        }
        
        
        /**
         * Create a new instance of UtcTimeSyntaxChecker
         * @return A new instance of UtcTimeSyntaxChecker
         */
        @Override
        public UtcTimeSyntaxChecker build()
        {
            return new UtcTimeSyntaxChecker( oid );
        }
    }

    
    /**
     * Creates a new instance of UtcTimeSyntaxChecker.
     *
     * @param oid The OID to use for this SyntaxChecker
     */
    private UtcTimeSyntaxChecker( String oid )
    {
        super( oid );
    }

    
    /**
     * @return An instance of the Builder for this class
     */
    public static Builder builder()
    {
        return new Builder();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isValidSyntax( Object value )
    {
        String strValue;

        if ( value == null )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, "null" ) );
            }
            
            return false;
        }

        if ( value instanceof String )
        {
            strValue = ( String ) value;
        }
        else if ( value instanceof byte[] )
        {
            strValue = Strings.utf8ToString( ( byte[] ) value );
        }
        else
        {
            strValue = value.toString();
        }

        // A generalized time must have a minimal length of 11 
        if ( strValue.length() < 11 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // Start the date parsing
        boolean result;
        
        synchronized ( DATE_PATTERN )
        {
            result = DATE_PATTERN.matcher( strValue ).find();
        }

        if ( result )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );
            }
        }
        else
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
        }
        
        return result;
    }
}
