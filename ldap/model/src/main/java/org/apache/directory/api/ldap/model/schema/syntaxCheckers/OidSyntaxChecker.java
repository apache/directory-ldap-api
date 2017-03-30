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
import org.apache.directory.api.util.Chars;
import org.apache.directory.api.util.Strings;


/**
 * A SyntaxChecker which verifies that a value is an oid according to RFC 4512.
 * <p>
 * From RFC 4512 :
 * <pre>
 * oid = descr | numericoid
 * descr = keystring
 * keystring = leadkeychar *keychar
 * leadkeychar = ALPHA
 * keychar = ALPHA | DIGIT | HYPHEN
 * number  = DIGIT | ( LDIGIT 1*DIGIT )
 * ALPHA   = %x41-5A | %x61-7A              ; "A"-"Z" | "a"-"z"
 * DIGIT   = %x30 | LDIGIT                  ; "0"-"9"
 * LDIGIT  = %x31-39                        ; "1"-"9"
 * HYPHEN  = %x2D                           ; hyphen ("-")
 * numericoid = number 1*( DOT number )
 * DOT     = %x2E                           ; period (".")
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class OidSyntaxChecker extends SyntaxChecker
{
    /**
     * A static instance of OidSyntaxChecker
     */
    public static final OidSyntaxChecker INSTANCE = new OidSyntaxChecker( SchemaConstants.OID_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<OidSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.OID_SYNTAX );
        }
        
        
        /**
         * Create a new instance of OidSyntaxChecker
         * @return A new instance of OidSyntaxChecker
         */
        @Override
        public OidSyntaxChecker build()
        {
            return new OidSyntaxChecker( oid );
        }
    }

    
    /**
     * Creates a new instance of OidSyntaxChecker.
     * 
     * @param oid The OID to use for this SyntaxChecker
     */
    private OidSyntaxChecker( String oid )
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

        // if the first character is a digit it's an attempt at an OID and must be
        // checked to make sure there are no other chars except '.' and digits.
        if ( Chars.isDigit( strValue.charAt( 0 ) ) )
        {
            boolean result = Oid.isOid(  strValue  );
            
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

        // here we just need to make sure that we have the right characters in the 
        // string and that it starts with a letter.
        if ( Chars.isAlphaASCII( strValue, 0 ) )
        {
            for ( int index = 0; index < strValue.length(); index++ )
            {
                char c = strValue.charAt( index );
                
                if ( !Chars.isAlphaDigitMinus( c ) )
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
        else
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }
    }
}
