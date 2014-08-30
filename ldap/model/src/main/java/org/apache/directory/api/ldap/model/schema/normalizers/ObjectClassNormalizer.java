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
package org.apache.directory.api.ldap.model.schema.normalizers;



import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.StringValue;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.util.Strings;


/**
 * Normalizer which deals with ObjectClass values. We just have to get rid of spaces 
 * at the beginning and the end of the name, and to lowercase the value.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@SuppressWarnings("serial")
public class ObjectClassNormalizer extends Normalizer
{
    /**
     * Creates a new instance of ObjectClassNormalizer.
     */
    public ObjectClassNormalizer()
    {
        super( SchemaConstants.OBJECT_CLASS_AT_OID );
    }


    /**
     * {@inheritDoc}
     */
    public Value<?> normalize( Value<?> value ) throws LdapException
    {
        if ( value == null )
        {
            return null;
        }

        String normalized = normalizeInternal( value.getString() );

        return new StringValue( normalized );
    }


    /**
     * {@inheritDoc}
     */
    public String normalize( String value ) throws LdapException
    {
        if ( value == null )
        {
            return "";
        }

        String normalized = normalizeInternal( value );
        
        return normalized;
    }
    
    
    /**
     * Normalize the ObjectClass value by removing the leading and training 
     * spaces, and lowercasing the value.
     */
    private String normalizeInternal( String str )
    {
        if ( Strings.isEmpty( str ) )
        {
            return "";
        }

        char[] chars = str.toCharArray();
        int length = chars.length;
        int startPos = 0;
        
        // Skip the starting spaces
        while ( ( startPos < length ) && ( chars[startPos] == ' ' ) )
        {
            startPos++;
        }
        
        // We only have spaces...
        if ( startPos == length )
        {
            return "";
        }
        
        // trim from right
        int endPos = length - 1;
        
        while ( ( endPos > 0 ) && ( chars[endPos] == ' ' ) )
        {
            endPos--;
        }
        
        // Now lowercase the chars
        int currPos = startPos;
        
        while ( currPos <= endPos )
        {
            chars[currPos] = Character.toLowerCase( chars[currPos] );
            currPos++;
        }
        
        return new String( chars, startPos, endPos - startPos + 1 );
    }
}
