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


import java.util.HashSet;
import java.util.Set;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.util.Chars;
import org.apache.directory.api.util.Strings;


/**
 * A SyntaxChecker which verifies that a value is a DSEType according to 
 * http://tools.ietf.org/id/draft-ietf-asid-ldapv3-attributes-03.txt, par 6.2.1.5 :
 * <pre>
 * &lt;DSEType&gt;    ::= '(' &lt;sp&gt;* &lt;DSEBit&gt; &lt;sp&gt;* &lt;DSEBitList&gt; ')'
 * &lt;DSEBitList&gt; ::= '$' &lt;sp&gt;* &lt;DSEBit&gt; &lt;sp&gt;* &lt;DSEBitList&gt; | e      
 * &lt;DSEBit&gt;     ::= 'root' | 'glue' | 'cp' | 'entry' | 'alias' | 'subr' |
 *                  'nssr' | 'supr' | 'xr' | 'admPoint' | 'subentry' |
 *                  'shadow' | 'zombie' | 'immSupr' | 'rhob' | 'sa'
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class DseTypeSyntaxChecker extends SyntaxChecker
{
    /** The DSE BITS keywords */
    private static final String[] DSE_BITS_STRINGS =
        {
            "root", "glue", "cp", "entry", "alias", "subr",
            "nssr", "supr", "xr", "admPoint", "subentry",
            "shadow", "zombie", "immSupr", "rhob", "sa"
    };

    /** The Set which contains the DESBits */
    private static final Set<String> DSE_BITS = new HashSet<>();
    
    /**
     * A static instance of DseTypeSyntaxChecker
     */
    public static final DseTypeSyntaxChecker INSTANCE = new DseTypeSyntaxChecker( SchemaConstants.DSE_TYPE_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<DseTypeSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.DSE_TYPE_SYNTAX );
        }
        
        
        /**
         * Create a new instance of DseTypeSyntaxChecker
         * @return A new instance of DseTypeSyntaxChecker
         */
        @Override
        public DseTypeSyntaxChecker build()
        {
            return new DseTypeSyntaxChecker( oid );
        }
    }

    
    /** Initialization of the country set */
    static
    {
        for ( String country : DSE_BITS_STRINGS )
        {
            DSE_BITS.add( country );
        }
    }


    /**
     * Creates a new instance of DSETypeSyntaxChecker.
     *
     * @param oid The OID to use for this SyntaxChecker
     */
    private DseTypeSyntaxChecker( String oid )
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

        // We must have at least '(cp)', '(xr)' or '(ca)'
        if ( strValue.length() < 4 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // Check the opening and closing parenthesis
        if ( ( strValue.charAt( 0 ) != '(' )
            || ( strValue.charAt( strValue.length() - 1 ) != ')' ) )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        Set<String> keywords = new HashSet<>();
        int len = strValue.length() - 1;
        boolean needKeyword = true;

        // 
        for ( int i = 1; i < len; /* */)
        {
            // Skip spaces
            while ( ( i < len ) && ( strValue.charAt( i ) == ' ' ) )
            {
                i++;
            }

            int pos = i;

            // Search for a keyword
            while ( ( i < len ) && Chars.isAlphaASCII( strValue, pos ) )
            {
                pos++;
            }

            if ( pos == i )
            {
                // No keyword : error
                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                }
                
                return false;
            }

            String keyword = strValue.substring( i, pos );
            i = pos;

            if ( !DSE_BITS.contains( keyword ) )
            {
                // Unknown keyword
                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                }
                
                return false;
            }

            // Check that the keyword has not been met
            if ( keywords.contains( keyword ) )
            {
                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                }
                
                return false;
            }

            keywords.add( keyword );
            needKeyword = false;

            // Skip spaces
            while ( ( i < len ) && ( strValue.charAt( i ) == ' ' ) )
            {
                i++;
            }

            // Do we have another keyword ?
            if ( ( i < len ) && ( strValue.charAt( i ) == '$' ) )
            {
                // yes
                i++;
                needKeyword = true;
                continue;
            }
        }

        // We are done
        if ( LOG.isDebugEnabled() )
        {
            if ( needKeyword )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            else
            {
                LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );
            }
        }

        return !needKeyword;
    }
}
