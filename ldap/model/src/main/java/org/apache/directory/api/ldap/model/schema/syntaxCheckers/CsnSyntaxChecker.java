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
import org.apache.directory.api.ldap.model.csn.Csn;
import org.apache.directory.api.ldap.model.csn.InvalidCSNException;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;


/**
 * An CSN syntax checker.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class CsnSyntaxChecker extends SyntaxChecker
{
    /**
     * A static instance of CsnSyntaxChecker
     */
    public static final CsnSyntaxChecker INSTANCE = new CsnSyntaxChecker( SchemaConstants.CSN_SYNTAX );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<CsnSyntaxChecker>
    {
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.CSN_SYNTAX );
        }
        
        
        /**
         * Create a new instance of CsnSyntaxChecker
         * @return A new instance of CsnSyntaxChecker
         */
        @Override
        public CsnSyntaxChecker build()
        {
            return new CsnSyntaxChecker( oid );
        }
    }

    
    /**
     * Creates a new instance of CsnSyntaxChecker.
     * 
     * @param oid The OID to use for this SyntaxChecker
     */
    private CsnSyntaxChecker( String oid )
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

        String csnStr = ( String ) value;

        // It must be a valid CSN : try to create a new one.
        try
        {
            boolean result = Csn.isValid( csnStr );

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
        catch ( InvalidCSNException icsne )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }
    }
}
