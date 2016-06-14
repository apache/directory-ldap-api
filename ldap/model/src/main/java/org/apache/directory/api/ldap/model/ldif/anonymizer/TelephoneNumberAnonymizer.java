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


import java.util.Map;


/**
 * An anonymizer for the TelephoneNumber attribute. We simply replace the digits by random digits.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class TelephoneNumberAnonymizer extends IntegerAnonymizer
{

    /**
     * Creates a new instance of TelephoneNumberAnonymizer.
     */
    public TelephoneNumberAnonymizer()
    {
        super();
    }

    
    /**
     * Creates a new instance of TelephoneNumberAnonymizer.
     * 
     * @param latestIntegerMap The map containing the latest integer value for each length 
     */
    public TelephoneNumberAnonymizer( Map<Integer, String> latestIntegerMap )
    {
        super( latestIntegerMap );
    }

    /**
     * Anonymize an attribute using pure random values (either chars of bytes, depending on the Attribute type)
     *
    public Attribute anonymize( Map<Value<String>, Value<String>> valueMap, Set<Value<String>> valueSet, Attribute attribute )
    {
        Attribute result = new DefaultAttribute( attribute.getAttributeType() );

        for ( Value<?> value : attribute )
        {
            Value<String> anonymized =  valueMap.get( value );
            
            if ( anonymized != null )
            {
                try
                {
                    result.add( anonymized.getString() );
                }
                catch ( LdapInvalidAttributeValueException e )
                {
                    // TODO : handle that
                }
            }
            else
            {
                if ( value instanceof StringValue )
                {
                    String strValue = value.getNormValue().toString();
                    int length = strValue.length();
    
                    // Same size
                    char[] newValue = new char[length];
    
                    for ( int i = 0; i < length; i++ )
                    {
                        char c = ( strValue.charAt( i ) );
                        
                        if ( Character.isDigit( c ) )
                        {
                            newValue[i] = ( char ) ( random.nextInt( '9' - '0' ) + '0' );
                        }
                        else
                        {
                            newValue[i] = c;
                        }
                    }
    
                    try
                    {
                        String newValueStr = new String( newValue );
                        result.add( newValueStr );
                        
                        Value<String> anonValue = new StringValue( attribute.getAttributeType(), newValueStr );
                        valueMap.put( ( Value<String> ) value, anonValue );
                    }
                    catch ( LdapInvalidAttributeValueException e )
                    {
                        // TODO : handle that
                    }
                }
                else
                {
                    byte[] byteValue = value.getBytes();
    
                    // Same size
                    byte[] newValue = new byte[byteValue.length];
    
                    for ( int i = 0; i < byteValue.length; i++ )
                    {
                        newValue[i] = ( byte ) random.nextInt();
                    }
    
                    try
                    {
                        result.add( newValue );
                    }
                    catch ( LdapInvalidAttributeValueException e )
                    {
                        // TODO : handle that
                    }
                }
            }
        }

        return result;
    }*/
}
