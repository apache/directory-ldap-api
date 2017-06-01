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
 * A SyntaxChecker which verifies that a value is a delivery method 
 * according to RFC 4517.
 * 
 * From RFC 4517 &amp; RFC 4512:
 * <pre>
 * DeliveryMethod = pdm *( WSP DOLLAR WSP pdm )
 *
 * pdm = "any" | "mhs" | "physical" | "telex" | "teletex" |
 *       "g3fax" | "g4fax" | "ia5" | "videotex" | "telephone"
 *           
 * WSP     = 0*SPACE  ; zero or more " "
 * DOLLAR  = %x24 ; dollar sign ("$")
 * SPACE   = %x20 ; space (" ")
 * </pre>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class DeliveryMethodSyntaxChecker extends SyntaxChecker
{
    private static final String[] PDMS =
        {
            "any", "mhs", "physical", "telex", "teletex",
            "g3fax", "g4fax", "ia5", "videotex", "telephone"
        };

    /** The Set which contains the delivery methods */
    private static final Set<String> DELIVERY_METHODS = new HashSet<>();

    /** Initialization of the delivery methods set */
    static
    {
        for ( String country : PDMS )
        {
            DELIVERY_METHODS.add( country );
        }
    }
    
    /**
     * A static instance of DeliveryMethodSyntaxChecker
     */
    public static final DeliveryMethodSyntaxChecker INSTANCE = 
        new DeliveryMethodSyntaxChecker( SchemaConstants.DELIVERY_METHOD_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<DeliveryMethodSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.DELIVERY_METHOD_SYNTAX );
        }
        
        
        /**
         * Create a new instance of DeliveryMethodSyntaxChecker
         * @return A new instance of DeliveryMethodSyntaxChecker
         */
        @Override
        public DeliveryMethodSyntaxChecker build()
        {
            return new DeliveryMethodSyntaxChecker( oid );
        }
    }


    /**
     * Creates a new instance of DeliveryMethodSyntaxChecker.
     *
     * @param oid The OID to use for this SyntaxChecker
     */
    private DeliveryMethodSyntaxChecker( String oid )
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
     * 
     * Check if the string contains a delivery method which has 
     * not already been found.
     * 
     * @param strValue The string we want to look into for a PDM 
     * @param pos The current position in the string
     * @param pdms The set containing all the PDM
     * @return if a Prefered Delivery Method is found in the given string, returns 
     * its position, otherwise, returns -1
     */
    private int isPdm( String strValue, int start, Set<String> pdms )
    {
        int pos = start;

        while ( Chars.isAlphaDigit( strValue, pos ) )
        {
            pos++;
        }

        // No ascii string, this is not a delivery method
        if ( pos == start )
        {
            return -1;
        }

        String pdm = strValue.substring( start, pos );

        if ( !DELIVERY_METHODS.contains( pdm ) )
        {
            // The delivery method is unknown
            return -1;
        }
        else
        {
            if ( pdms.contains( pdm ) )
            {
                // The delivery method has already been found
                return -1;
            }
            else
            {
                pdms.add( pdm );
                return pos;
            }
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

        // We will get the first delivery method
        int length = strValue.length();
        int pos = 0;
        Set<String> pmds = new HashSet<>();

        pos = isPdm( strValue, pos, pmds );
        
        if ( pos == -1 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // We have found at least the first pmd,
        // now iterate through the other ones. We may have
        // SP* '$' SP* before each pmd.
        while ( pos < length )
        {
            // Skip spaces
            while ( Strings.isCharASCII( strValue, pos, ' ' ) )
            {
                pos++;
            }

            if ( !Strings.isCharASCII( strValue, pos, '$' ) )
            {
                // A '$' was expected
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

            // Skip spaces
            while ( Strings.isCharASCII( strValue, pos, ' ' ) )
            {
                pos++;
            }

            pos = isPdm( strValue, pos, pmds );
            
            if ( pos == -1 )
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
