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


import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.util.Chars;
import org.apache.directory.api.util.Strings;


/**
 * A SyntaxChecker which verifies that a value is a Boolean according to RFC 4517.
 * <br>
 * From RFC 4512 &amp; RFC 4517 :
 * <pre>
 * BitString    = SQUOTE *binary-digit SQUOTE "B"
 * binary-digit = "0" / "1"
 * SQUOTE       = %x27                           ; hyphen ("'")
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class BitStringSyntaxChecker extends SyntaxChecker
{
    /**
     * A static instance of BitStringSyntaxChecker
     */
    public static final BitStringSyntaxChecker INSTANCE = new BitStringSyntaxChecker( SchemaConstants.BIT_STRING_SYNTAX );

    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<BitStringSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.BIT_STRING_SYNTAX );
        }
        
        
        /**
         * Create a new instance of BitStringSyntaxChecker
         * @return A new instance of BitStringSyntaxChecker
         */
        @Override
        public BitStringSyntaxChecker build()
        {
            return new BitStringSyntaxChecker( oid );
        }
    }

    
    /**
     * Creates a new instance of BitStringSyntaxChecker.
     *
     * @param oid The OID to use for this SyntaxChecker
     */
    private BitStringSyntaxChecker( String oid )
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
     * A shared and static method used to check that the string is a BitString.
     * A BitString is a string of bits, between quotes and followed by a 'B' :
     * 
     * '01010110'B for instance
     * 
     * @param strValue The string to check
     * @return <code>true</code> if the string is a BitString
     */
    public static boolean isValid( String strValue )
    {
        if ( strValue.length() == 0 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, strValue ) );
            }
            
            return false;
        }

        int pos = 0;

        // Check that the String respect the syntax : ' ([01]+) ' B
        if ( !Strings.isCharASCII( strValue, pos++, '\'' ) )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, strValue ) );
            }
            
            return false;
        }

        // We must have at least one bit
        if ( !Chars.isBit( strValue, pos++ ) )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, strValue ) );
            }
            
            return false;
        }

        while ( Chars.isBit( strValue, pos ) )
        {
            // Loop until we get a char which is not a 0 or a 1
            pos++;
        }

        // Now, we must have a simple quote 
        if ( !Strings.isCharASCII( strValue, pos++, '\'' ) )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, strValue ) );
            }
            
            return false;
        }

        // followed by a 'B'
        if ( !Strings.isCharASCII( strValue, pos, 'B' ) )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, strValue ) );
            }
            
            return false;
        }

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, strValue ) );
        }
        
        return true;
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

        return isValid( strValue );
    }
}
