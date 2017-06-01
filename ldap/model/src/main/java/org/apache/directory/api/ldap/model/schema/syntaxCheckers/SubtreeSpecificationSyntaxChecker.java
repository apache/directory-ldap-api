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


import java.text.ParseException;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;
import org.apache.directory.api.ldap.model.subtree.SubtreeSpecificationChecker;
import org.apache.directory.api.util.Strings;


/**
 * A SyntaxChecker which verifies that a value is a subtree specification.
 * <p>
 * It has been removed in RFC 4517
 *  
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public final class SubtreeSpecificationSyntaxChecker extends SyntaxChecker
{
    /** The associated checker */
    private transient SubtreeSpecificationChecker subtreeSpecificationChecker;
    
    /**
     * A static instance of SubtreeSpecificationSyntaxChecker
     */
    public static final SubtreeSpecificationSyntaxChecker INSTANCE = 
        new SubtreeSpecificationSyntaxChecker( SchemaConstants.SUBTREE_SPECIFICATION_SYNTAX, null );
    
    /**
     * A static Builder for this class
     */
    public static final class Builder extends SCBuilder<SubtreeSpecificationSyntaxChecker>
    {
        /** The schemaManager */
        private SchemaManager schemaManager;
        
        /**
         * The Builder constructor
         */
        private Builder()
        {
            super( SchemaConstants.SUBTREE_SPECIFICATION_SYNTAX );
        }
        
        
        public Builder setSchemaManager( SchemaManager schemaManager )
        {
            this.schemaManager = schemaManager;
                
            return this;
        }
        
        
        /**
         * Create a new instance of SubtreeSpecificationSyntaxChecker
         * @return A new instance of SubtreeSpecificationSyntaxChecker
         */
        @Override
        public SubtreeSpecificationSyntaxChecker build()
        {
            return new SubtreeSpecificationSyntaxChecker( oid, schemaManager );
        }
    }
    
    /**
     * Creates an instance of SubtreeSpecificationSyntaxChecker
     * 
     * @param oid The OID to use for this SyntaxChecker
     */
    private SubtreeSpecificationSyntaxChecker( String oid, SchemaManager schemaManager )
    {
        super( oid );
        subtreeSpecificationChecker = new SubtreeSpecificationChecker( schemaManager );
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

        try
        {
            synchronized ( subtreeSpecificationChecker )
            {
                subtreeSpecificationChecker.parse( strValue );
            }

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );
            }
            
            return true;
        }
        catch ( ParseException pe )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.err( I18n.ERR_04488_SYNTAX_INVALID, value ) );
            }
            
            return false;
        }
    }
}
