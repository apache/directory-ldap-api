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
 *  KIND, eCopyOfUuidSyntaxCheckerither express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.directory.api.ldap.model.schema.syntaxCheckers;


import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;


/**
 * An CSN SID syntax checker.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class CsnSidSyntaxChecker extends SyntaxChecker
{
    /**
     * A static instance of CsnSidSyntaxChecker
     */
    public static final CsnSidSyntaxChecker INSTANCE = new CsnSidSyntaxChecker( SchemaConstants.CSN_SID_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<CsnSidSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.CSN_SID_SYNTAX );
        }
        
        
        /**
         * Create a new instance of CsnSidSyntaxChecker
         * @return A new instance of CsnSidSyntaxChecker
         */
        @Override
        public CsnSidSyntaxChecker build()
        {
            return new CsnSidSyntaxChecker( oid );
        }
    }

    
    /**
     * Creates a new instance of CsnSyntaxChecker.
     * 
     * @param oid The OID to use for this SyntaxChecker
     */
    private CsnSidSyntaxChecker( String oid )
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
        if ( value == null )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, "null" ) );
            }
            
            return false;
        }

        if ( !( value instanceof String ) )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        String sidStr = ( String ) value;

        if ( sidStr.length() > 3 )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }

        // The SID must be an hexadecimal number between 0x00 and 0xFFF

        try
        {
            int sid = Integer.parseInt( sidStr, 16 );

            if ( ( sid < 0 ) || ( sid > 0x0fff ) )
            {
                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
                }
                
                return false;
            }
        }
        catch ( NumberFormatException nfe )
        {
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
