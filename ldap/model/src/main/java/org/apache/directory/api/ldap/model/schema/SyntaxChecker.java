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
package org.apache.directory.api.ldap.model.schema;

import org.apache.directory.api.i18n.I18n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Used to validate values of a particular syntax. This interface does not
 * correlate to any LDAP or X.500 construct. It has been created as a means to
 * enforce a syntax within the Eve server.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class SyntaxChecker extends LoadableSchemaObject
{
    /** The mandatory serialVersionUID */
    public static final long serialVersionUID = 1L;
    
    /** A logger for this class */
    protected static final Logger LOG = LoggerFactory.getLogger( SyntaxChecker.class );

    /**
     * A static Builder for this class
     */
    public abstract static class SCBuilder<SC>
    {
        /** The SyntaxChecker OID */
        protected String oid;
        
        /**
         * The Builder constructor
         */
        protected SCBuilder( String oid )
        {
            this.oid = oid;
        }
        
        
        /**
         * Set the SyntaxChecker's OID
         * 
         * @param oid The OID
         * @return The Builder's Instance
         */
        public SCBuilder<SC> setOid( String oid )
        {
            this.oid = oid;
            
            return this;
        }
        
        public abstract SC build();
    }


    /**
     * The SyntaxChecker base constructor
     * @param oid The associated OID
     */
    protected SyntaxChecker( String oid )
    {
        super( SchemaObjectType.SYNTAX_CHECKER, oid );
    }


    /**
     * The SyntaxChecker default constructor where the oid is set after 
     * instantiation.
     */
    protected SyntaxChecker()
    {
        super( SchemaObjectType.SYNTAX_CHECKER );
    }


    /**
     * Determines if the attribute's value conforms to the attribute syntax.
     * 
     * @param value the value of some attribute with the syntax
     * @return true if the value is in the valid syntax, false otherwise
     */
    public boolean isValidSyntax( Object value )
    {
        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_04489_SYNTAX_VALID, value ) );
        }
        
        return true;
    }


    /**
     * Store the SchemaManager in this instance. It may be necessary for some
     * syntaxChecker which needs to have access to the oidNormalizer Map.
     *
     * @param schemaManager the schemaManager to store
     */
    public void setSchemaManager( SchemaManager schemaManager )
    {
        // Do nothing (general case).
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals( Object o )
    {
        if ( !super.equals( o ) )
        {
            return false;
        }

        return o instanceof SyntaxChecker;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        return objectType + " " + DescriptionUtils.getDescription( this );
    }
}
