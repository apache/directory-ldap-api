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
 * A SyntaxChecker which verifies that a value is a TeletexTerminalIdentifier according to 
 * RFC 4517 :
 * <pre>
 * teletex-id = ttx-term *(DOLLAR ttx-param)
 * ttx-term   = PrintableString          ; terminal identifier
 * ttx-param  = ttx-key COLON ttx-value  ; parameter
 * ttx-key    = "graphic" | "control" | "misc" | "page" | "private"
 * ttx-value  = *ttx-value-octet
 *
 * ttx-value-octet = %x00-23 | (%x5C "24") | %x25-5B | (%x5C "5C") | %x5D-FF
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class TeletexTerminalIdentifierSyntaxChecker extends SyntaxChecker
{
    /**
     * A static instance of TeletexTerminalIdentifierSyntaxChecker
     */
    public static final TeletexTerminalIdentifierSyntaxChecker INSTANCE = 
        new TeletexTerminalIdentifierSyntaxChecker( SchemaConstants.TELETEX_TERMINAL_IDENTIFIER_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<TeletexTerminalIdentifierSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.TELETEX_TERMINAL_IDENTIFIER_SYNTAX );
        }
        
        
        /**
         * Create a new instance of TeletexTerminalIdentifierSyntaxChecker
         * @return A new instance of TeletexTerminalIdentifierSyntaxChecker
         */
        @Override
        public TeletexTerminalIdentifierSyntaxChecker build()
        {
            return new TeletexTerminalIdentifierSyntaxChecker( oid );
        }
    }

    
    /**
     * Creates a new instance of TeletexTerminalIdentifier.
     * 
     * @param oid the child's OID
     */
    private TeletexTerminalIdentifierSyntaxChecker( String oid )
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

        String terminalIdentifier = ( dollar == -1 ) ? strValue : strValue.substring( 0, dollar );

        if ( terminalIdentifier.length() == 0 )
        {
            // It should not be null
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        if ( !Strings.isPrintableString( terminalIdentifier ) )
        {
            // It's not a valid PrintableString 
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        if ( dollar == -1 )
        {
            // No ttx-param : let's get out
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );
            }
            
            return true;
        }

        // Ok, now let's deal with optional ttx-params
        String[] ttxParams = strValue.substring( dollar + 1 ).split( "\\$" );

        if ( ttxParams.length == 0 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
                
            return false;
        }

        for ( String ttxParam : ttxParams )
        {
            int colon = ttxParam.indexOf( ':' );

            if ( colon == -1 )
            {
                // we must have a ':' separator
                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                }
                
                return false;
            }

            String key = ttxParam.substring( 0, colon );

            if ( key.startsWith( "graphic" )
                || key.startsWith( "control" )
                || key.startsWith( "misc" )
                || key.startsWith( "page" )
                || key.startsWith( "private" ) )
            {
                if ( colon + 1 == ttxParam.length() )
                {
                    if ( LOG.isDebugEnabled() )
                    {
                        LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                    }
                    
                    return false;
                }

                boolean hasEsc = false;

                for ( byte b : Strings.getBytesUtf8( ttxParam ) )
                {
                    switch ( b )
                    {
                        case 0x24:
                            // '$' is not accepted
                            if ( LOG.isDebugEnabled() )
                            {
                                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                            }
                            
                            return false;

                        case 0x5c:
                            if ( hasEsc )
                            {
                                // two following \ are not accepted
                                if ( LOG.isDebugEnabled() )
                                {
                                    LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                                }
                                
                                return false;
                            }
                            else
                            {
                                hasEsc = true;
                            }

                            continue;

                        case '2':
                            continue;

                        case '4':
                            // We have found a "\24"
                            hasEsc = false;
                            continue;

                        case '5':
                            continue;

                        case 'c':
                        case 'C':
                            // We have found a "\5c" or a "\5C"
                            hasEsc = false;
                            continue;

                        default:
                            if ( hasEsc )
                            {
                                // A \ should be followed by "24" or "5c" or "5C"
                                return false;
                            }

                            continue;
                    }
                }
            }
            else
            {
                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                }
                
                return false;
            }
        }

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );
        }
        
        return true;
    }
}
