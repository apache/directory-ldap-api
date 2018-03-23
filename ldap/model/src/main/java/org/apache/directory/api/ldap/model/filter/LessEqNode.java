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
package org.apache.directory.api.ldap.model.filter;


import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapSchemaException;
import org.apache.directory.api.ldap.model.schema.AttributeType;


/**
 * A assertion value node for LessOrEqual.
 * 
 * @param <T> The Value type
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LessEqNode<T> extends SimpleNode<T>
{
    /**
     * Creates a new LessEqNode object.
     * 
     * @param attributeType the attributeType
     * @param value the value to test for
     * @throws LdapSchemaException If the AttributeType does not have an ORDERING MatchingRule
     */
    public LessEqNode( AttributeType attributeType, Value value ) throws LdapSchemaException
    {
        super( attributeType, value, AssertionType.LESSEQ );
        
        // Check if the AttributeType has an Ordering MR
        if ( ( attributeType != null ) && ( attributeType.getOrdering() == null ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13301_NO_ORDERING_MR_FOR_AT, attributeType.getName() ) );
        }
    }


    /**
     * Creates a new LessEqNode object.
     * 
     * @param attribute the attribute name
     * @param value the value to test for
     * @throws LdapSchemaException If the AttributeType does not have an ORDERING MatchingRule
     */
    public LessEqNode( String attribute, byte[] value ) throws LdapSchemaException
    {
        super( attribute, value, AssertionType.LESSEQ );

        // Check if the AttributeType has an Ordering MR
        if ( ( attributeType != null ) && ( attributeType.getOrdering() == null ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13301_NO_ORDERING_MR_FOR_AT, attributeType.getName() ) );
        }
    }


    /**
     * Creates a new LessEqNode object.
     * 
     * @param attribute the attribute name
     * @param value the value to test for
     * @throws LdapSchemaException If the AttributeType does not have an ORDERING MatchingRule
     */
    public LessEqNode( String attribute, String value ) throws LdapSchemaException
    {
        super( attribute, value, AssertionType.LESSEQ );

        // Check if the AttributeType has an Ordering MR
        if ( ( attributeType != null ) && ( attributeType.getOrdering() == null ) )
        {
            throw new LdapSchemaException( I18n.err( I18n.ERR_13301_NO_ORDERING_MR_FOR_AT, attributeType.getName() ) );
        }
    }


    /**
     * @see Object#toString()
     * @return A string representing the AndNode
     */
    @Override
    public String toString()
    {
        StringBuilder buf = new StringBuilder();

        buf.append( '(' );

        if ( attributeType != null )
        {
            buf.append( attributeType.getName() );
        }
        else
        {
            buf.append( attribute );
        }

        buf.append( "<=" );

        String escapedValue = getEscapedValue();
        
        if ( escapedValue != null )
        {
            buf.append( escapedValue );
        }

        buf.append( super.toString() );

        buf.append( ')' );

        return buf.toString();
    }
}
