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
 * A SyntaxChecker which verifies that a value is a DSAQualitySyntax according to 
 * http://tools.ietf.org/id/draft-ietf-asid-ldapv3-attributes-03.txt, par 5.2.2.2 :
 * <pre>
 * &lt;DsaQualitySyntax&gt; ::= &lt;DSAKeyword&gt; [ '#' &lt;description&gt; ]
 *
 * &lt;DSAKeyword&gt; ::= 'DEFUNCT' | 'EXPERIMENTAL' | 'BEST-EFFORT' |
 *                  'PILOT-SERVICE' | 'FULL-SERVICE'
 *
 * &lt;description&gt; ::= encoded as a PrintableString
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class DsaQualitySyntaxSyntaxChecker extends SyntaxChecker
{
    /**
     * A static instance of DsaQualitySyntaxSyntaxChecker
     */
    public static final DsaQualitySyntaxSyntaxChecker INSTANCE = 
        new DsaQualitySyntaxSyntaxChecker( SchemaConstants.DSA_QUALITY_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<DsaQualitySyntaxSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.DSA_QUALITY_SYNTAX );
        }
        
        
        /**
         * Create a new instance of DsaQualitySyntaxSyntaxChecker
         * @return A new instance of DsaQualitySyntaxSyntaxChecker
         */
        @Override
        public DsaQualitySyntaxSyntaxChecker build()
        {
            return new DsaQualitySyntaxSyntaxChecker( oid );
        }
    }

    
    /**
     * Creates a new instance of DSAQualitySyntaxSyntaxChecker.
     * 
     * @param oid The OID to use for this SyntaxChecker
     */
    private DsaQualitySyntaxSyntaxChecker( String oid )
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

        if ( strValue.length() < 7 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        String remaining;

        switch ( strValue.charAt( 0 ) )
        {
            case 'B':
                if ( !strValue.startsWith( "BEST-EFFORT" ) )
                {
                    if ( LOG.isDebugEnabled() )
                    {
                        LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                    }
                    
                    return false;
                }

                remaining = strValue.substring( "BEST-EFFORT".length() );
                break;

            case 'D':
                if ( !strValue.startsWith( "DEFUNCT" ) )
                {
                    if ( LOG.isDebugEnabled() )
                    {
                        LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                    }
                    
                    return false;
                }

                remaining = strValue.substring( "DEFUNCT".length() );
                break;

            case 'E':
                if ( !strValue.startsWith( "EXPERIMENTAL" ) )
                {
                    if ( LOG.isDebugEnabled() )
                    {
                        LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                    }
                    
                    return false;
                }

                remaining = strValue.substring( "EXPERIMENTAL".length() );
                break;

            case 'F':
                if ( !strValue.startsWith( "FULL-SERVICE" ) )
                {
                    if ( LOG.isDebugEnabled() )
                    {
                        LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                    }
                    
                    return false;
                }

                remaining = strValue.substring( "FULL-SERVICE".length() );
                break;

            case 'P':
                if ( !strValue.startsWith( "PILOT-SERVICE" ) )
                {
                    if ( LOG.isDebugEnabled() )
                    {
                        LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                    }
                    
                    return false;
                }

                remaining = strValue.substring( "PILOT-SERVICE".length() );
                break;

            default:
                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                }
                
                return false;
        }

        // Now, we might have a description separated from the keyword by a '#'
        // but this is optional
        if ( remaining.length() == 0 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );
            }
            
            return true;
        }

        if ( remaining.charAt( 0 ) != '#' )
        {
            // We were expecting a '#'
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // Check that the description is a PrintableString
        boolean result = Strings.isPrintableString( remaining.substring( 1 ) );

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
