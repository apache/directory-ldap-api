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
package org.apache.directory.shared.ldap.model.schema;


import org.apache.directory.shared.ldap.model.exception.LdapException;
import org.apache.directory.shared.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.shared.ldap.model.message.ResultCodeEnum;


/**
 * Used to validate values of a particular syntax. This interface does not
 * correlate to any LDAP or X.500 construct. It has been created as a means to
 * enforce a syntax within the Eve server.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractSyntaxChecker extends MutableLoadableSchemaObjectImpl implements MutableSyntaxChecker
{
    private static final long serialVersionUID = -6028809434764891692L;


    /**
     * The SyntaxChecker base constructor
     * @param oid The associated OID
     */
    protected AbstractSyntaxChecker( String oid )
    {
        super( SchemaObjectType.SYNTAX_CHECKER, oid );
    }


    /**
     * The SyntaxChecker default constructor where the oid is set after 
     * instantiation.
     */
    protected AbstractSyntaxChecker()
    {
        super( SchemaObjectType.SYNTAX_CHECKER );
    }
    
    
    /**
     * {@inheritDoc}
     */
    public SyntaxChecker copy()
    {
        return new AbstractSyntaxChecker()
        {
            private static final long serialVersionUID = 1L;

            @Override
            public boolean isValidSyntax( Object value )
            {
                return this.isValidSyntax( value );
            }
        };
    }

    
    /**
     * {@inheritDoc}
     */
    public MutableSyntaxChecker copyMutable()
    {
        return new AbstractSyntaxChecker()
        {
            private static final long serialVersionUID = 1L;

            @Override
            public boolean isValidSyntax( Object value )
            {
                return this.isValidSyntax( value );
            }
        };
    }
    

    public abstract boolean isValidSyntax( Object value );


    public void assertSyntax( Object value ) throws LdapException
    {
        if ( !isValidSyntax( value ) )
        {
            throw new LdapInvalidAttributeValueException( ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX );
        }
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

        return o instanceof AbstractSyntaxChecker;
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
