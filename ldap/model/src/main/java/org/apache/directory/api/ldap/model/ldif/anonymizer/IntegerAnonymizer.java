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


import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.StringValue;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;


/**
 * A default anonymizer for attributes that is an Integer. the initial value is randomized
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class IntegerAnonymizer extends AbstractAnonymizer<String>
{
    /** The latest anonymized Integer value map */
    private Map<Integer, String> latestIntegerMap;

    /**
     * Creates a new instance of IntegerAnonymizer.
     */
    public IntegerAnonymizer()
    {
        latestIntegerMap = new HashMap<>();
    }

    
    /**
     * Creates a new instance of IntegerAnonymizer.
     * 
     * @param latestIntegerMap The map containing the latest integer value for each length 
     */
    public IntegerAnonymizer( Map<Integer, String> latestIntegerMap )
    {
        if ( latestIntegerMap == null ) 
        {
            this.latestIntegerMap = new HashMap<>();
        }
        else
        {
            this.latestIntegerMap = latestIntegerMap;
        }
    }

    /**
     * Anonymize an attribute using pure random values (either chars of bytes, depending on the Attribute type)
     */
    @Override
    public Attribute anonymize( Map<Value<String>, Value<String>> valueMap, Set<Value<String>> valueSet, Attribute attribute )
    {
        Attribute result = new DefaultAttribute( attribute.getAttributeType() );

        for ( Value<?> value : attribute )
        {
            if ( value instanceof StringValue )
            {
                Value<String> anonymized =  valueMap.get( value );
                
                if ( anonymized != null )
                {
                    try
                    {
                        result.add( anonymized );
                    }
                    catch ( LdapInvalidAttributeValueException e )
                    {
                        // Handle me...
                    }
                }
                else
                {
                    String strValue = value.getNormValue().toString();
                    String newValue = computeNewIntegerValue( strValue );
    
                    try
                    {
                        result.add( newValue );
                        Value<String> anonValue = new StringValue( attribute.getAttributeType(), newValue );
                        valueMap.put( ( Value<String> ) value, anonValue );
                        valueSet.add( anonValue );
                    }
                    catch ( LdapInvalidAttributeValueException e )
                    {
                        // TODO : handle that
                    }
                }
            }
        }

        return result;
    }
    

    /**
     * @return The Map containing the latest anonymized value for each integer
     */
    public Map<Integer, String> getLatestIntegerMap()
    {
        return latestIntegerMap;
    }
    
    
    /**
     * Set the Map containing anonymized integers
     * @param latestIntegerMap The Map containing the latest anonymized value for each integer
     */
    public void setLatestIntegerMap( Map<Integer, String> latestIntegerMap )
    {
        this.latestIntegerMap = latestIntegerMap;
    }

    
    /**
     * Compute the next Integer value
     *
     * @param valStr The original value
     * @return The anonymized value
     */
    private String computeNewIntegerValue( String valStr )
    {
        int length = valStr.length();
        String latestInteger = latestIntegerMap.get( length );
        
        if ( latestInteger == null )
        {
            // No previous value : create a new one
            char[] newValue = new char[length];
            
            Arrays.fill( newValue, '9' );
            
            String anonymizedValue = new String( newValue );
            latestIntegerMap.put( length, anonymizedValue );
            
            return anonymizedValue;
        }
        else
        {
            // Compute a new value
            char[] latest = latestInteger.toCharArray();
            boolean overflow = true;
            
            for ( int i = length - 1; i >= 0; i-- )
            {
                if ( latest[i] == '0' )
                {
                    latest[i] = '9';
                }
                else
                {
                    latest[i]--;
                    overflow = false;
                    break;
                }
            }
            
            // Corner case : we can't have a value starting with '0' unless its length is 1
            if ( ( length > 1 ) && ( latest[0] == '0' ) )
            {
                throw new RuntimeException( "Overflow for " + valStr );
            }
            
            String anonymizedValue = new String( latest );
            
            if ( overflow )
            {
                // We have exhausted all the possible values...
                throw new RuntimeException( "Cannot compute a new value for " + anonymizedValue );
            }
            
            latestIntegerMap.put( length, anonymizedValue );
            
            return anonymizedValue;
        }
    }
}
