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
 * A SyntaxChecker which verifies that a value is a Numeric String according to RFC 4517.
 * <p>
 * From RFC 4517 :
 * <pre>
 * NumericString = 1*(DIGIT / SPACE)
 * 
 * From RFC 4512 :
 * DIGIT   = %x30 | LDIGIT       ; "0"-"9"
 * LDIGIT  = %x31-39             ; "1"-"9"
 * SPACE   = %x20                ; space (" ")
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class NumericStringSyntaxChecker extends SyntaxChecker
{
    /**
     * A static instance of NumericStringSyntaxChecker
     */
    public static final NumericStringSyntaxChecker INSTANCE = 
        new NumericStringSyntaxChecker( SchemaConstants.NUMERIC_STRING_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<NumericStringSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.NUMERIC_STRING_SYNTAX );
        }
        
        
        /**
         * Create a new instance of NumericStringSyntaxChecker
         * @return A new instance of NumericStringSyntaxChecker
         */
        @Override
        public NumericStringSyntaxChecker build()
        {
            return new NumericStringSyntaxChecker( oid );
        }
    }

    
    /**
     * Creates a new instance of NumericStringSyntaxChecker.
     * 
     * @param oid The OID to use for this SyntaxChecker
     */
    private NumericStringSyntaxChecker( String oid )
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

        // We should have at least one char
        if ( strValue.length() == 0 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // Check that each char is either a digit or a space
        for ( int i = 0; i < strValue.length(); i++ )
        {
            switch ( strValue.charAt( i ) )
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
                case ' ':
                    continue;

                default:
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
