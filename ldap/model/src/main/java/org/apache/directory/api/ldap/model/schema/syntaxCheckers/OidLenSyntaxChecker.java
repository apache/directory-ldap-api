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


import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.util.Strings;


/**
 * A SyntaxChecker which verifies that a value is a numeric oid and a length
 * constraint according to RFC 4512.
 * <p>
 * From RFC 4512 :
 * <pre>
 * noidlen    = numericoid [ LCURLY len RCURLY ]
 * numericoid = number 1*( DOT number )
 * len        = number
 * number     = DIGIT | ( LDIGIT 1*DIGIT )
 * DIGIT      = %x30 | LDIGIT                  ; "0"-"9"
 * LDIGIT     = %x31-39                        ; "1"-"9"
 * DOT        = %x2E                           ; period (".")
 * LCURLY  = %x7B                              ; left curly brace "{"
 * RCURLY  = %x7D                              ; right curly brace "}"
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class OidLenSyntaxChecker extends SyntaxChecker
{
    /**
     * A static instance of OidLenSyntaxChecker
     */
    public static final OidLenSyntaxChecker INSTANCE = 
        new OidLenSyntaxChecker( SchemaConstants.OID_LEN_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<OidLenSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.OID_LEN_SYNTAX );
        }
        
        
        /**
         * Create a new instance of OidLenSyntaxChecker
         * @return A new instance of OidLenSyntaxChecker
         */
        @Override
        public OidLenSyntaxChecker build()
        {
            return new OidLenSyntaxChecker( oid );
        }
    }

    
    /**
     * 
     * Creates a new instance of OidLenSyntaxChecker.
     *
     */
    private OidLenSyntaxChecker( String oid )
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

        // We are looking at the first position of the len part
        int pos = strValue.indexOf( '{' );

        if ( pos < 0 )
        {
            // Not found ... but it may still be a valid OID
            boolean result = Oid.isOid( strValue );

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
        else
        {
            // we should have a len value. First check that the OID is valid
            String oid = strValue.substring( 0, pos );

            if ( !Oid.isOid( oid ) )
            {
                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                }
                
                return false;
            }

            String len = strValue.substring( pos );

            // We must have a number and a '}' at the end
            if ( len.charAt( len.length() - 1 ) != '}' )
            {
                // No final '}'
                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                }
                
                return false;
            }

            for ( int i = 1; i < len.length() - 1; i++ )
            {
                switch ( len.charAt( i ) )
                {
                    case '0':
                    case '1':
                    case '2':
                    case '3':
                    case '4':
                    case '5':
                    case '6':
                    case '7':
                    case '8':
                    case '9':
                        break;

                    default:
                        if ( LOG.isDebugEnabled() )
                        {
                            LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                        }
                        
                        return false;
                }
            }

            if ( ( len.charAt( 1 ) == '0' ) && len.length() > 3 )
            {
                // A number can't start with a '0' unless it's the only
                // number
                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                }
                
                return false;
            }

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );
            }
            
            return true;
        }
    }
}
