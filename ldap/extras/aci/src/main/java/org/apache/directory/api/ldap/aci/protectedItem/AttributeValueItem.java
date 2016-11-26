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
package org.apache.directory.api.ldap.aci.protectedItem;


import java.util.Collections;
import java.util.Iterator;
import java.util.Set;

import org.apache.directory.api.ldap.aci.ProtectedItem;
import org.apache.directory.api.ldap.model.entry.Attribute;


/**
 * A specific value of specific attributes.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AttributeValueItem extends ProtectedItem
{
    /** The protected Attributes */
    private final Set<Attribute> attributes;


    /**
     * Creates a new instance.
     * 
     * @param attributes the collection of {@link Attribute}s.
     */
    public AttributeValueItem( Set<Attribute> attributes )
    {
        this.attributes = Collections.unmodifiableSet( attributes );
    }


    /**
     * Returns an iterator of all {@link org.apache.directory.api.ldap.model.entry.Attribute}s.
     *
     * @return the iterator
     */
    public Iterator<Attribute> iterator()
    {
        return attributes.iterator();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int hashCode()
    {
        int hash = 37;
        
        if ( attributes != null )
        {
            for ( Attribute attribute : attributes )
            {
                hash = hash * 17 + attribute.hashCode();
            }
        }
        
        return hash;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean equals( Object o )
    {
        if ( this == o )
        {
            return true;
        }

        if ( o instanceof AttributeValueItem )
        {
            AttributeValueItem that = ( AttributeValueItem ) o;

            if ( attributes != null )
            {
                if ( ( that.attributes == null ) || ( that.attributes.size() != attributes.size() ) )
                {
                    return false;
                }
                
                for ( Attribute attribute : attributes )
                {
                    if ( !that.attributes.contains( attribute ) )
                    {
                        return false;
                    }
                }
                
                return true;
            }
            else
            {
                return attributes == null;
            }
        }

        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        StringBuilder buf = new StringBuilder();

        buf.append( "attributeValue {" );

        boolean isFirst = true;

        if ( attributes != null )
        {
            for ( Attribute attribute : attributes )
            {
                if ( isFirst )
                {
                    isFirst = false;
                }
                else
                {
                    buf.append( ", " );
                }
    
                buf.append( attribute.getId() );
                buf.append( '=' );
                buf.append( attribute.get() );
            }
        }

        buf.append( " }" );

        return buf.toString();
    }
}
