/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */

package org.apache.directory.api.ldap.model.ldif.anonymizer;


import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.BinaryValue;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;


/**
 * A default anonymizer for attributes that are not HR
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class BinaryAnonymizer extends AbstractAnonymizer<byte[]>
{
    /** The latest anonymized byte[] value map */
    protected Map<Integer, byte[]> latestBytesMap = new HashMap<>();

    /**
     * Creates a new instance of BinaryAnonymizer.
     */
    public BinaryAnonymizer()
    {
        latestBytesMap = new HashMap<>();
    }

    
    /**
     * Creates a new instance of BinaryAnonymizer.
     * 
     * @param latestBytesMap The map containing the latest value for each length 
     */
    public BinaryAnonymizer( Map<Integer, byte[]> latestBytesMap )
    {
        if ( latestBytesMap == null )
        {
            this.latestBytesMap = new HashMap<>();
        }
        else
        {
            this.latestBytesMap = latestBytesMap;
        }
    }

    /**
     * Anonymize an attribute using pure random values (either chars of bytes, depending on the Attribute type)
     */
    @Override
    public Attribute anonymize( Map<Value<byte[]>, Value<byte[]>> valueMap, Set<Value<byte[]>> valueSet, Attribute attribute )
    {
        Attribute result = new DefaultAttribute( attribute.getAttributeType() );

        for ( Value<?> value : attribute )
        {
            byte[] bytesValue = ( byte[] ) value.getNormValue();
            byte[] newValue = computeNewValue( bytesValue );
            
            try
            {
                result.add( newValue );
                Value<byte[]> anonValue = new BinaryValue( attribute.getAttributeType(), newValue );
                valueMap.put( ( Value<byte[]> ) value, anonValue );
                valueSet.add( anonValue );
            }
            catch ( LdapInvalidAttributeValueException e )
            {
                throw new RuntimeException( "Error while anonymizing the value" + value );
            }
        }

        return result;
    }
    
    
    /**
     * {@inheritDoc}
     */
    @Override
    public Map<Integer, byte[]> getLatestBytesMap()
    {
        return latestBytesMap;
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public void setLatestBytesMap( Map<Integer, byte[]> latestBytesMap )
    {
        this.latestBytesMap = latestBytesMap;
    }
}
