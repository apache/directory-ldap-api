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
 * A SyntaxChecker which verifies that a value is a Directory String according to RFC 4517.
 * 
 * From RFC 4517 :
 * 
 * <pre>
 * DirectoryString = 1*UTF8
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class DirectoryStringSyntaxChecker extends SyntaxChecker
{
    /**
     * A static instance of DirectoryStringSyntaxChecker
     */
    public static final DirectoryStringSyntaxChecker INSTANCE = 
        new DirectoryStringSyntaxChecker( SchemaConstants.DIRECTORY_STRING_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<DirectoryStringSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.DIRECTORY_STRING_SYNTAX );
        }
        
        
        /**
         * Create a new instance of DirectoryStringSyntaxChecker
         * @return A new instance of DirectoryStringSyntaxChecker
         */
        @Override
        public DirectoryStringSyntaxChecker build()
        {
            return new DirectoryStringSyntaxChecker( oid );
        }
    }

    
    /**
     * Creates a new instance of DirectoryStringSyntaxChecker.
     * 
     * @param oid The OID to use for this SyntaxChecker
     */
    private DirectoryStringSyntaxChecker( String oid )
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

        // If the value was an invalid UTF8 string, then it's length
        // will be 0 as the StringTools.utf8ToString() call will
        // return an empty string
        if ( strValue.length() == 0 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // In any other case, we have to check that the
        // string does not contains the '0xFFFD' character
        for ( char c : strValue.toCharArray() )
        {
            if ( c == 0xFFFD )
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
