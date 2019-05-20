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
 * A SyntaxChecker which verifies that a value is a NisNetGroupTriple according to 
 * RFC 2307 :
 * <pre>
 * nisnetgrouptriple = "(" hostname "," username "," domainname ")"
 *      hostname          = "" / "-" / keystring
 *      username          = "" / "-" / keystring
 *      domainname        = "" / "-" / keystring
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class NisNetgroupTripleSyntaxChecker extends SyntaxChecker
{
    /**
     * A static instance of NisNetGroupTripleChecker
     */
    public static final NisNetgroupTripleSyntaxChecker INSTANCE = 
        new NisNetgroupTripleSyntaxChecker( SchemaConstants.NIS_NETGROUP_TRIPLE_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<NisNetgroupTripleSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.NIS_NETGROUP_TRIPLE_SYNTAX );
        }
        
        
        /**
         * Create a new instance of NisNetgroupTripleSyntaxChecker
         * @return A new instance of NisNetgroupTripleSyntaxChecker
         */
        @Override
        public NisNetgroupTripleSyntaxChecker build()
        {
            return new NisNetgroupTripleSyntaxChecker( oid );
        }
    }

    
    /**
     * Creates a new instance of NisNetgroupTripleSyntaxChecker.
     * 
     * @param oid The OID to use for this SyntaxChecker
     */
    private NisNetgroupTripleSyntaxChecker( String oid )
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
    
    
    private int parseKeyString( String strValue, int pos )
    {
        char c = strValue.charAt( pos );
        
        // The end of the keyString
        if ( ( c == ',' ) || ( c == ')' ) )
        {
            return pos;
        }
        
        // We must have a first alphabetic char
        if ( Character.isUpperCase( c ) || Character.isLowerCase( c ) )
        {
            pos++;
        }
        else
        {
            return -1;
        }
        
        try 
        { 
            c = strValue.charAt( pos );
            
            while ( ( c != ',') && ( c != ')' ) )
            {
                if ( Character.isUpperCase( c ) || Character.isLowerCase( c ) || Character.isDigit( c ) ||
                    ( c == '-' ) || ( c == ';' ) || ( c == '_' ) )
                {
                    pos++;
                }
                else
                {
                    return -1;
                }

                c = strValue.charAt( pos );
            }
            
            return pos;
        }
        catch ( IndexOutOfBoundsException ioobe )
        {
            return -1;
        }
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
                LOG.debug( I18n.err( I18n.ERR_13210_SYNTAX_INVALID, "null" ) );
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

        // The  nisNetGroup must at least contain a '(', 2 ',' and a ')'
        if ( strValue.length() < 4 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_13210_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // The hostname
        int pos = parseKeyString( strValue, 1 );
        
        if ( pos == -1 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_13210_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }
        
        if ( strValue.charAt( pos ) != ',' )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_13210_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }
        else
        {
            pos++;
        }

        // The username
        pos = parseKeyString( strValue, pos );
        
        if ( pos == -1 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_13210_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }
        
        if ( strValue.charAt( pos ) != ',' )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_13210_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }
        else
        {
            pos++;
        }

        // The domainname
        pos = parseKeyString( strValue, pos );
        
        if ( pos == -1 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_13210_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }
        
        if ( strValue.charAt( pos ) != ')' )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_13210_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        return true;
    }
}
