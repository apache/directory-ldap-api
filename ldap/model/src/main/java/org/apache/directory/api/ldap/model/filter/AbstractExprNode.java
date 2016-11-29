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


import java.util.HashMap;
import java.util.Map;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.entry.BinaryValue;
import org.apache.directory.api.ldap.model.entry.StringValue;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.util.Strings;


/**
 * Abstract implementation of a expression node.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractExprNode implements ExprNode
{
    /** The map of annotations */
    protected Map<String, Object> annotations;

    /** The node type */
    protected final AssertionType assertionType;

    /** A flag set to true if the Node is Schema aware */
    protected boolean isSchemaAware;


    /**
     * Creates a node by setting abstract node type.
     * 
     * @param assertionType The node's type
     */
    protected AbstractExprNode( AssertionType assertionType )
    {
        this.assertionType = assertionType;
    }


    /**
     * @see ExprNode#getAssertionType()
     * 
     * @return the node's type
     */
    @Override
    public AssertionType getAssertionType()
    {
        return assertionType;
    }


    /**
     * @see Object#equals(Object)
     *@return <code>true</code> if both objects are equal 
     */
    @Override
    public boolean equals( Object o )
    {
        // Shortcut for equals object
        if ( this == o )
        {
            return true;
        }

        if ( !( o instanceof AbstractExprNode ) )
        {
            return false;
        }

        AbstractExprNode that = ( AbstractExprNode ) o;

        // Check the node type
        if ( this.assertionType != that.assertionType )
        {
            return false;
        }

        if ( annotations == null )
        {
            return that.annotations == null;
        }
        else if ( that.annotations == null )
        {
            return false;
        }

        // Check all the annotation
        for ( Map.Entry<String, Object> entry : annotations.entrySet() )
        {
            String key = entry.getKey();
        
            if ( !that.annotations.containsKey( key ) )
            {
                return false;
            }

            Object thisAnnotation = entry.getValue();
            Object thatAnnotation = that.annotations.get( key );

            if ( thisAnnotation == null )
            {
                if ( thatAnnotation != null )
                {
                    return false;
                }
            }
            else
            {
                if ( !thisAnnotation.equals( thatAnnotation ) )
                {
                    return false;
                }
            }
        }

        return true;
    }


    /**
     * Handles the escaping of special characters in LDAP search filter assertion values using the
     * &lt;valueencoding&gt; rule as described in
     * <a href="http://www.ietf.org/rfc/rfc4515.txt">RFC 4515</a>. Needed so that
     * {@link ExprNode#printRefinementToBuffer(StringBuilder)} results in a valid filter string that can be parsed
     * again (as a way of cloning filters).
     *
     * @param value Right hand side of "attrId=value" assertion occurring in an LDAP search filter.
     * @return Escaped version of <code>value</code>
     */
    protected static Value<?> escapeFilterValue( Value<?> value )
    {
        if ( value.isNull() )
        {
            return value;
        }

        StringBuilder sb;
        String val;

        if ( !value.isHumanReadable() )
        {
            sb = new StringBuilder( ( ( BinaryValue ) value ).getReference().length * 3 );

            for ( byte b : ( ( BinaryValue ) value ).getReference() )
            {
                if ( ( b < 0x7F ) && ( b >= 0 ) )
                {
                    switch ( b )
                    {
                        case '*':
                            sb.append( "\\2A" );
                            break;

                        case '(':
                            sb.append( "\\28" );
                            break;

                        case ')':
                            sb.append( "\\29" );
                            break;

                        case '\\':
                            sb.append( "\\5C" );
                            break;

                        case '\0':
                            sb.append( "\\00" );
                            break;

                        default:
                            sb.append( ( char ) b );
                    }
                }
                else
                {
                    sb.append( '\\' );
                    String digit = Integer.toHexString( b & 0x00FF );

                    if ( digit.length() == 1 )
                    {
                        sb.append( '0' );
                    }

                    sb.append( Strings.upperCase( digit ) );
                }
            }

            return new StringValue( sb.toString() );
        }

        val = ( ( StringValue ) value ).getString();
        String encodedVal = FilterEncoder.encodeFilterValue( val );
        if ( val.equals( encodedVal ) )
        {
            return value;
        }
        else
        {
            return new StringValue( encodedVal );
        }
    }


    /**
     * @see Object#hashCode()
     * @return the instance's hash code 
     */
    @Override
    public int hashCode()
    {
        int h = 37;

        if ( annotations != null )
        {
            for ( Map.Entry<String, Object> entry : annotations.entrySet() )
            {
                String key = entry.getKey();
                Object value = entry.getValue();

                h = h * 17 + key.hashCode();
                h = h * 17 + ( value == null ? 0 : value.hashCode() );
            }
        }

        return h;
    }


    /**
     * @see ExprNode#get(java.lang.Object)
     * 
     * @return the annotation value.
     */
    @Override
    public Object get( Object key )
    {
        if ( null == annotations )
        {
            return null;
        }

        return annotations.get( key );
    }


    /**
     * @see ExprNode#set(String, java.lang.Object)
     */
    @Override
    public void set( String key, Object value )
    {
        if ( null == annotations )
        {
            annotations = new HashMap<>( 2 );
        }

        annotations.put( key, value );
    }


    /**
     * Gets the annotations as a Map.
     * 
     * @return the annotation map.
     */
    protected Map<String, Object> getAnnotations()
    {
        return annotations;
    }


    /**
     * Tells if this Node is Schema aware.
     * 
     * @return true if the Node is SchemaAware
     */
    @Override
    public boolean isSchemaAware()
    {
        return isSchemaAware;
    }


    /**
     * Default implementation for this method : just throw an exception.
     * 
     * @param buf the buffer to append to.
     * @return The buffer in which the refinement has been appended
     * @throws UnsupportedOperationException if this node isn't a part of a refinement.
     */
    @Override
    public StringBuilder printRefinementToBuffer( StringBuilder buf )
    {
        throw new UnsupportedOperationException( I18n.err( I18n.ERR_04144 ) );
    }


    /**
     * Clone the object
     */
    @Override
    public ExprNode clone()
    {
        try
        {
            ExprNode clone = ( ExprNode ) super.clone();

            if ( annotations != null )
            {
                for ( Map.Entry<String, Object> entry : annotations.entrySet() )
                {
                    // Note : the value aren't cloned ! 
                    ( ( AbstractExprNode ) clone ).annotations.put( entry.getKey(), entry.getValue() );
                }
            }

            return clone;
        }
        catch ( CloneNotSupportedException cnse )
        {
            return null;
        }
    }


    /**
     * @see Object#toString()
     */
    @Override
    public String toString()
    {
        if ( ( null != annotations ) && annotations.containsKey( "count" ) )
        {
            Long count = ( Long ) annotations.get( "count" );

            if ( count == Long.MAX_VALUE )
            {
                return ":[\u221E]";
            }

            return ":[" + count + "]";
        }
        else
        {
            return "";
        }
    }
}
