/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    https://www.apache.org/licenses/LICENSE-2.0
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


import java.io.Serializable;
import java.util.Comparator;

import org.apache.directory.api.ldap.model.schema.normalizers.NoOpNormalizer;


/**
 * An class used for Comparator. It inherits from the general AbstractAdsSchemaObject class. It
 * also implements the Comparator interface
 * 
 * @param <T> The comparator type
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class LdapComparator<T> extends LoadableSchemaObject implements Comparator<T>, Serializable
{
    /** Declares the Serial Version Uid */
    private static final long serialVersionUID = 2L;

    /** A default normalizer*/
    protected Normalizer normalizer = new NoOpNormalizer();

    /**
     * Create a new instance of a Comparator
     * @param oid The associated OID
     */
    protected LdapComparator( String oid )
    {
        super( SchemaObjectType.COMPARATOR, oid );
    }


    /**
     * Store the SchemaManager in this instance. It may be necessary for some
     * comparator which needs to have access to the oidNormalizer Map.
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
    public int hashCode()
    {
        int hash = h;
        
        if ( normalizer != null )
        {
            hash = hash * 17 + normalizer.hashCode();
        }
        
        return hash;
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
        
        if ( !( o instanceof LdapComparator<?> ) )
        {
            return false;
        }
        
        LdapComparator<?> that = ( LdapComparator<?> ) o; 
        
        // Compare the normalizer
        if ( normalizer != null )
        {
            return normalizer.equals( that.getNormalizer() );
        }
        else 
        {
            return that.getNormalizer() == null;
        }
    }
    
    
    /**
     * @return The associated normalizer
     */
    public Normalizer getNormalizer()
    {
        return normalizer;
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
