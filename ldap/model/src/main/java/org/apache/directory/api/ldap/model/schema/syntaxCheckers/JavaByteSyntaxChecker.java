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
 * A SyntaxChecker which verifies that a value is a valid Java primitive short or
 * the Short wrapper.  Essentially this constrains the min and max values of
 * the Integer.
 * <p>
 * From RFC 4517 :
 *
 * <pre>
 * Integer = ( HYPHEN LDIGIT *DIGIT ) | number
 *
 * From RFC 4512 :
 * number  = DIGIT | ( LDIGIT 1*DIGIT )
 * DIGIT   = %x30 | LDIGIT       ; "0"-"9"
 * LDIGIT  = %x31-39             ; "1"-"9"
 * HYPHEN  = %x2D                ; hyphen ("-")
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class JavaByteSyntaxChecker extends SyntaxChecker
{
    /**
     * A static instance of JavaByteSyntaxChecker
     */
    public static final JavaByteSyntaxChecker INSTANCE = new JavaByteSyntaxChecker( SchemaConstants.JAVA_BYTE_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<JavaByteSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.JAVA_BYTE_SYNTAX );
        }
        
        
        /**
         * Create a new instance of JavaByteSyntaxChecker
         * @return A new instance of JavaByteSyntaxChecker
         */
        @Override
        public JavaByteSyntaxChecker build()
        {
            return new JavaByteSyntaxChecker( oid );
        }
    }


    /**
     * Creates a new instance of JavaByteSyntaxChecker.
     * 
     * @param oid The OID to use for this SyntaxChecker
     */
    private JavaByteSyntaxChecker( String oid )
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

        // The first char must be either a '-' or in [0..9].
        // If it's a '0', then there should be any other char after
        int pos = 0;
        char c = strValue.charAt( pos );

        if ( c == '-' )
        {
            pos = 1;
        }
        else if ( !Chars.isDigit( c ) )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }
        else if ( c == '0' )
        {
            boolean result = strValue.length() <= 1;
            
            if ( LOG.isDebugEnabled() )
            {
                if ( result )
                {
                    LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                }
                else
                {
                    LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );
                }
            }
            
            return result;
        }

        // We must have at least a digit which is not '0'
        if ( !Chars.isDigit( strValue, pos ) || Strings.isCharASCII( strValue, pos, '0' ) )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }
        else
        {
            pos++;
        }

        while ( Chars.isDigit( strValue, pos ) )
        {
            pos++;
        }

        if ( pos != strValue.length() )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // Should get a NumberFormatException for Byte values out of range
        try
        {
            Byte.valueOf( strValue );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );
            }
            
            return true;
        }
        catch ( NumberFormatException e )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }
    }
}
