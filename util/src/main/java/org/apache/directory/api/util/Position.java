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
package org.apache.directory.api.util;


/**
 *
 * This class is used to store the position of a token in a string.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class Position
{
    /** The starting position in the string */
    public int start = 0;

    /** The current token length */
    public int length = 0;

    /** The token end position in the string */
    public int end = 0;
    
    /** The parsed text. It's only used by the toString function */
    private String text;
    
    /** The parsed text as a UTF-8 byte array */
    byte[] bytes;
    
    /**
     * A public constructor
     */
    public Position()
    {
        // Nothing to do
    }
    
    
    /**
     * A public constructor
     * 
     * @param text The String to parse
     */
    public Position( String text )
    {
        this.text = text;
    }
    
    
    /**
     * A public constructor
     * 
     * @param bytes The bytes to parse
     */
    public Position( byte[] bytes )
    {
        this.bytes = bytes;
    }
    
    
    /**
     * Get the byte at the current position
     * 
     * @return the byte at the current position
     */
    public byte getByte()
    {
        return bytes[start];
    }
    
    
    /**
     * Get the stored bytes
     * 
     * @return The interned byte[]
     */
    public byte[] getBytes()
    {
        return bytes;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        if ( text != null )
        {
            String head = text.substring( Math.max( start - 10, 0 ), start );
            String tail = text.substring( Math.min( start + 1, length ), Math.min( start + 10, length ) );
            
            if ( start == length )
            {
                return "'..." + head + "'";
            }
            else
            {
                return "'..." + head + "'[" + text.charAt( start ) + "]'" + tail 
                        + "...' [" + start + ", " + end + ", " + length + "]";
            }
        }
        else if ( bytes != null )
        {
            int head = Math.max( start - 10, 0 );
            int tail = Math.min( start + 1, length );
            
            if ( start == length )
            {
                return "'..." + ( char ) bytes[start - 1] + "[]'";
            }
            else
            {
                StringBuilder sb = new StringBuilder();
                sb.append( "'" );
                
                for ( int i = head; i < start; i++ )
                {
                    byte b = bytes[i];
                    
                    if ( ( b >= 0x20 ) && ( b <= 0x7F ) )
                    {
                        sb.append( ( char ) b );
                    }
                    else
                    {
                        sb.append( Strings.byteToString( b ) );
                    }
                }

                sb.append( "'[" );
                byte b = bytes[start];
                
                if ( ( b >= 0x20 ) && ( b <= 0x7F ) )
                {
                    sb.append( ( char ) b );
                }
                else
                {
                    sb.append( Strings.byteToString( b ) );
                }

                sb.append( "]'" );

                for ( int i = start + 1; i < tail; i++ )
                {
                    b = bytes[i];
                    
                    if ( ( b >= 0x20 ) && ( b <= 0x7F ) )
                    {
                        sb.append( ( char ) b );
                    }
                    else
                    {
                        sb.append( Strings.byteToString( b ) );
                    }
                }
                
                sb.append( "...' [" ).
                    append( start ).
                    append( ", " ).
                    append( end ).
                    append( ", " ).
                    append( length ).
                    append( "]" );
                
                return sb.toString();
            }
        }
        
        return "[" + start + ", " + end + ", " + length + "]";
    }
}
