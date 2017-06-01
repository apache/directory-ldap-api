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
import org.apache.directory.api.util.Strings;


/**
 * A SyntaxChecker which verifies that a value is a Telex Number according to 
 * RFC 4517 :
 * <pre>
 * telex-number  = actual-number DOLLAR country-code DOLLAR answerback
 * actual-number = PrintableString
 * country-code  = PrintableString
 * answerback    = PrintableString
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class TelexNumberSyntaxChecker extends SyntaxChecker
{
    /**
     * A static instance of TelexNumberSyntaxChecker
     */
    public static final TelexNumberSyntaxChecker INSTANCE = 
        new TelexNumberSyntaxChecker( SchemaConstants.TELEX_NUMBER_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<TelexNumberSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.TELEX_NUMBER_SYNTAX );
        }
        
        
        /**
         * Create a new instance of TelexNumberSyntaxChecker
         * @return A new instance of TelexNumberSyntaxChecker
         */
        @Override
        public TelexNumberSyntaxChecker build()
        {
            return new TelexNumberSyntaxChecker( oid );
        }
    }

    
    /**
     * Creates a new instance of TelexNumberSyntaxChecker.
     * 
     * @param oid the child's OID
     */
    private TelexNumberSyntaxChecker( String oid )
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

        if ( strValue.length() == 0 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // Search for the first '$' separator
        int dollar = strValue.indexOf( '$' );

        // We must have one, and not on first position
        if ( dollar <= 0 )
        {
            // No '$' => error
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        String actualNumber = strValue.substring( 0, dollar );

        // The actualNumber must not be empty
        if ( actualNumber.length() == 0 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // The actual number should be a PrintableString 
        if ( !Strings.isPrintableString( actualNumber ) )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // Search for the second separator
        int dollar2 = strValue.indexOf( '$', dollar + 1 );

        // We must have one
        if ( dollar2 == -1 )
        {
            // No '$' => error
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        String countryCode = strValue.substring( dollar + 1, dollar2 );

        // The countryCode must not be empty
        if ( countryCode.length() == 0 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // The country Code should be a PrintableString 
        if ( !Strings.isPrintableString( countryCode ) )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // Now, check for the answerBack
        if ( dollar2 + 1 == strValue.length() )
        {
            // The last string should not be null
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        String answerBack = strValue.substring( dollar2 + 1 );

        // The answerBack should be a PrintableString 
        if ( !Strings.isPrintableString( answerBack ) )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // Check that the mailboxType is a PrintableString
        boolean result = Strings.isPrintableString( answerBack );

        if ( LOG.isDebugEnabled() )
        {
            if ( result )
            {
                LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );
            }
            else
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
        }

        return result;
    }
}
