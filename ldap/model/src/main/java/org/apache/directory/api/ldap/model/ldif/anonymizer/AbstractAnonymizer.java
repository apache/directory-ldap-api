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

import org.apache.directory.api.ldap.model.schema.SchemaManager;

/**
 * An abstract class implementing the default behavior of an Anonymizer instance
 * 
 * @param <K> The type of object being anonymized
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractAnonymizer<K> implements Anonymizer<K>
{
    /** The SchemaManager instance */
    protected SchemaManager schemaManager;
    
    /** The map of AttributeType'sOID we want to anonymize. They are all associated with anonymizers */
    protected Map<String, Anonymizer<K>> attributeAnonymizers = new HashMap<>();
    
    /** A flag set to <tt>true</tt> if the AttributeType is case sensitive */
    protected boolean caseSensitive = false;
    
    /** Map of chars to use in the anonymized values 0    5    10   15   20   25   30   35   40*/
    private static final char[] NOT_SENSITIVE_MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'()-./".toCharArray();
    private static final char[] SENSITIVE_MAP =     "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'()-./abcdefghijklmnopqrstuvwxyz".toCharArray();
    
    /** A table containing booleans when the corresponding char is printable */
    private static final int[] CHAR_MAP =
        {
            // ---, ---, ---, ---, ---, ---, ---, ---
                0,   0,   0,   0,   0,   0,   0,   0, 
            // ---, ---, ---, ---, ---, ---, ---, ---
                0,   0,   0,   0,   0,   0,   0,   0, 
            // ---, ---, ---, ---, ---, ---, ---, ---
                0,   0,   0,   0,   0,   0,   0,   0, 
            // ---, ---, ---, ---, ---, ---, ---, ---
                0,   0,   0,   0,   0,   0,   0,   0, 
            // ---, ---, ---, ---, ---, ---, ---, "'"
                0,   0,   0,   0,   0,   0,   0,  36, 
            // '(', ')', ---, '+', ',', '-', '.', '/'
               37,  38,   0,   0,   0,  39,  40,  41, 
            // '0', '1', '2', '3', '4', '5', '6', '7',
               26,  27,  28,  29,  30,  31,  32,  33, 
            // '8', '9', ':', ---, ---, '=', ---, '?'
               34,  35,   0,   0,   0,   0,   0,  26, 
            // ---, 'A', 'B', 'C', 'D', 'E', 'F', 'G',
                0,   0,   1,   2,   3,   4,   5,   6, 
            // 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O'
                7,   8,   9,  10,  11,  12,  13,  14, 
            // 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W'
               15,  16,  17,  18,  19,  20,  21,  22, 
            // 'X', 'Y', 'Z', ---, ---, ---, ---, ---
               23,  24,  25,   0,   0,   0,   0,   0, 
            // ---, 'a', 'b', 'c', 'd', 'e', 'f', 'g'
                0,  42,  43,  44,  45,  46,  47,  48, 
            // 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o'
               49,  50,  51,  52,  53,  54,  55,  56, 
            // 'p', 'q', 'r', 's', 't', 'u', 'v', 'w'
               57,  58,  59,  60,  61,  62,  63,  64, 
            // 'x', 'y', 'z', ---, ---, ---, ---, ---
               65,  66,  67,   0,   0,   0,   0,   0, 
    };

    /**
     * {@inheritDoc}
     */
    @Override
    public void setSchemaManager( SchemaManager schemaManager )
    {
        this.schemaManager = schemaManager;
    }
    
    
    /**
     * Set the list of existing anonymizers
     *
     * @param attributeAnonymizers The list of existing anonymizers
     */
    @Override
    public void setAnonymizers( Map<String, Anonymizer<K>> attributeAnonymizers )
    {
        this.attributeAnonymizers = attributeAnonymizers;
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public Map<Integer, String> getLatestStringMap()
    {
        return null;
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public void setLatestStringMap( Map<Integer, String> latestStringMap )
    {
        // Do nothing
    }

    
    /**
     * {@inheritDoc}
     */
    @Override
    public Map<Integer, byte[]> getLatestBytesMap()
    {
        return null;
    }
    
    
    /**
     * {@inheritDoc}
     */
    @Override
    public void setLatestBytesMap( Map<Integer, byte[]> latestBytesMap )
    {
        // Do nothing
    }
    
    
    /**
     * Compute the next String value
     *
     * @param valStr The original value
     * @return The anonymized value
     */
    protected String computeNewValue( String valStr )
    {
        int length = valStr.length();
        String latestString = getLatestStringMap().get( length );
        char[] charMap;
        
        if ( caseSensitive )
        {
            charMap = SENSITIVE_MAP;
        }
        else
        {
            charMap = NOT_SENSITIVE_MAP;
        }
        
        int lastMapChar = charMap.length - 1;

        if ( latestString == null )
        {
            // No previous value : create a new one
            char[] newValue = new char[length];
            
            Arrays.fill( newValue, charMap[0] );
            
            String anonymizedValue = new String( newValue );
            getLatestStringMap().put( length, anonymizedValue );
            
            return anonymizedValue;
        }
        else
        {
            // Compute a new value
            char[] latest = latestString.toCharArray();
            boolean overflow = true;
            
            for ( int i = length - 1; i >= 0; i-- )
            {
                if ( latest[i] == charMap[lastMapChar] )
                {
                    latest[i] = charMap[0];
                }
                else
                {
                    latest[i] = charMap[CHAR_MAP[latest[i]] + 1];
                    overflow = false;
                    break;
                }
            }
            
            String anonymizedValue = new String( latest );
            
            if ( overflow )
            {
                // We have exhausted all the possible values...
                throw new RuntimeException( "Cannot compute a new value for " + anonymizedValue );
            }
            
            getLatestStringMap().put( length, anonymizedValue );
            
            return anonymizedValue;
        }
    }
    
    
    /**
     * Compute the next byte[] value
     *
     * @param valBytes The original value
     * @return The anonymized value
     */
    protected byte[] computeNewValue( byte[] valBytes )
    {
        int length = valBytes.length;
        byte[] latestBytes = getLatestBytesMap().get( length );
        
        if ( latestBytes == null )
        {
            // No previous value : create a new one
            byte[] newValue = new byte[length];
            
            Arrays.fill( newValue, ( byte ) 'A' );
            
            getLatestBytesMap().put( length, newValue );
            
            return newValue;
        }
        else
        {
            // Compute a new value
            boolean overflow = true;
            
            for ( int i = length - 1; i >= 0; i-- )
            {
                if ( latestBytes[i] == ( byte ) 'Z' )
                {
                    latestBytes[i] = ( byte ) 'A';
                }
                else
                {
                    latestBytes[i]++;
                    overflow = false;
                    break;
                }
            }
            
            if ( overflow )
            {
                // We have exhausted all the possible values...
                throw new RuntimeException( "Cannot compute a new value for " + latestBytes );
            }
            
            return latestBytes;
        }
    }
}
