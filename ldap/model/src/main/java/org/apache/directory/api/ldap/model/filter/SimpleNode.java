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
package org.apache.directory.api.ldap.model.filter;


import java.util.Arrays;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.util.Strings;


/**
 * A simple assertion value node.
 * 
 * @param <T> The Value type
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class SimpleNode<T> extends LeafNode
{
    /** the value */
    protected Value value;
    
    /** The value as a byte[] */
    protected byte[] bytes;

    /** Constants for comparisons : @gt; */
    public static final boolean EVAL_GREATER = true;

    /** Constants for comparisons : &lt; */
    public static final boolean EVAL_LESSER = false;


    /**
     * Creates a new SimpleNode object.
     * 
     * @param attribute the attribute name
     * @param bytes the data to inject
     * @param assertionType the type of assertion represented by this ExprNode
     */
    protected SimpleNode( String attribute, byte[] bytes, AssertionType assertionType )
    {
        super( attribute, assertionType );
        this.bytes = bytes;
    }


    /**
     * Creates a new SimpleNode object.
     * 
     * @param attributeType the attribute name
     * @param bytes the data to inject
     * @param assertionType the type of assertion represented by this ExprNode
     */
    protected SimpleNode( AttributeType attributeType, byte[] bytes, AssertionType assertionType )
    {
        super( attributeType, assertionType );
        this.bytes = bytes;
        
        try
        {
            if ( attributeType.isHR() )
            {
                value = new Value( attributeType, Strings.utf8ToString( bytes ) );
            }
            else
            {
                    value = new Value( attributeType, bytes );
            }
        }
        catch ( LdapInvalidAttributeValueException e )
        {
            throw new RuntimeException( e.getMessage() );
        }
    }


    /**
     * Creates a new SimpleNode object.
     * 
     * @param attribute the attribute name
     * @param string the value to inject
     * @param assertionType the type of assertion represented by this ExprNode
     */
    protected SimpleNode( String attribute, String string, AssertionType assertionType )
    {
        super( attribute, assertionType );
        bytes = Strings.getBytesUtf8( string );
        
        if ( attributeType != null )
        {
            try
            {
                if ( attributeType.isHR() )
                {
                    value = new Value( attributeType, string );
                }
                else
                {
                    value = new Value( attributeType, bytes );
                }
            }
            catch ( LdapInvalidAttributeValueException e )
            {
                throw new RuntimeException( e.getMessage() );
            }
        }
    }


    /**
     * Creates a new SimpleNode object.
     * 
     * @param attributeType the attribute name
     * @param value the value to test for
     * @param assertionType the type of assertion represented by this ExprNode
     */
    protected SimpleNode( AttributeType attributeType, Value value, AssertionType assertionType )
    {
        super( attributeType, assertionType );
        this.value = value;
    }


    /**
     * Makes a full clone in new memory space of the current node and children
     */
    @SuppressWarnings("unchecked")
    @Override
    public ExprNode clone()
    {
        ExprNode clone = super.clone();

        // Clone the value, if we have one
        if ( value != null )
        {
            ( ( SimpleNode<T> ) clone ).value = value.clone();
        }
        else
        {
            // clone the bytes if any
            if ( bytes != null )
            {
                ( ( SimpleNode<T> ) clone ).bytes = new byte[bytes.length];
                System.arraycopy( bytes, 0, ( ( SimpleNode<T> ) clone ).bytes, 0, bytes.length );
            }
        }

        return clone;
    }


    /**
     * Gets the value.
     * 
     * @return the value
     */
    public final Value getValue()
    {
        if ( value == null )
        {
            return new Value( bytes );
        }
        else
        {
            return value;
        }
    }


    /** 
     * @return representation of value, escaped for use in a filter if required 
     */
    public String getEscapedValue()
    {
        if ( value != null )
        {
            return escapeFilterValue( value.getAttributeType(), value.getBytes() );
        }
        else
        {
            return escapeFilterValue( null, bytes );
        }
    }


    /**
     * Sets the value of this node.
     * 
     * @param value the value for this node
     */
    public void setValue( Value value )
    {
        this.value = value;
        this.bytes = value.getBytes();
    }


    /**
     * Pretty prints this expression node along with annotation information.
     *
     * @param buf the buffer to print into
     * @return the same buf argument returned for call chaining
     */
    public StringBuilder printToBuffer( StringBuilder buf )
    {
        if ( ( null != getAnnotations() ) && getAnnotations().containsKey( "count" ) )
        {
            buf.append( ":[" );
            buf.append( getAnnotations().get( "count" ).toString() );
            buf.append( "] " );
        }

        buf.append( ')' );

        return buf;
    }


    /**
     * @see ExprNode#printRefinementToBuffer(StringBuilder)
     * @return The buffer in which the refinement has been appended
     * @throws UnsupportedOperationException if this node isn't a part of a refinement.
     */
    @Override
    public StringBuilder printRefinementToBuffer( StringBuilder buf )
    {
        if ( isSchemaAware() )
        {
            if ( !attributeType.getOid().equals( SchemaConstants.OBJECT_CLASS_AT_OID ) )
            {
                throw new UnsupportedOperationException( I18n.err( I18n.ERR_13318_INVALID_ATTR_IN_REFINEMENT, attribute ) );
            }
        }
        else
        {
            if ( ( attribute == null )
                || !( SchemaConstants.OBJECT_CLASS_AT.equalsIgnoreCase( attribute )
                || SchemaConstants.OBJECT_CLASS_AT_OID.equalsIgnoreCase( attribute ) ) )
            {
                throw new UnsupportedOperationException( I18n.err( I18n.ERR_13318_INVALID_ATTR_IN_REFINEMENT, attribute ) );
            }
        }

        buf.append( "item: " ).append( value );

        return buf;
    }


    /**
     * @see Object#hashCode()
     * @return the instance's hash code 
     */
    @Override
    public int hashCode()
    {
        int h = 37;

        h = h * 17 + super.hashCode();
        h = h * 17 + ( value == null ? 0 : value.hashCode() );

        return h;
    }


    /**
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals( Object other )
    {
        if ( this == other )
        {
            return true;
        }

        if ( !( other instanceof SimpleNode<?> ) )
        {
            return false;
        }

        if ( other.getClass() != this.getClass() )
        {
            return false;
        }

        if ( !super.equals( other ) )
        {
            return false;
        }

        SimpleNode<?> otherNode = ( SimpleNode<?> ) other;

        if ( value == null )
        {
            if ( bytes == null )
            {
                return otherNode.bytes == null;
            }
            else
            {
                return Arrays.equals( bytes,  otherNode.bytes );
            }
        }
        else
        {
            return value.equals( otherNode.value );
        }
    }
}
