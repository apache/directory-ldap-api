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


import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.util.Strings;


/**
 * Abstract base class for leaf nodes within the expression filter tree.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class LeafNode extends AbstractExprNode
{
    /** attributeType on which this leaf is based */
    protected AttributeType attributeType;

    /** attribute on which this leaf is based */
    protected String attribute;


    /**
     * Creates a leaf node.
     * 
     * @param attributeType the attribute this node is based on
     * @param assertionType the type of this leaf node
     */
    protected LeafNode( AttributeType attributeType, AssertionType assertionType )
    {
        super( assertionType );
        this.attributeType = attributeType;

        if ( attributeType != null )
        {
            this.attribute = attributeType.getName();
        }
        else
        {
            throw new NullPointerException( I18n.err( I18n.ERR_13302_CANNOT_CREATE_NODE_NULL_ATTR ) );
        }
    }


    /**
     * Creates a leaf node.
     * 
     * @param attributeType the attribute this node is based on
     * @param assertionType the type of this leaf node
     */
    protected LeafNode( String attribute, AssertionType assertionType )
    {
        super( assertionType );
        this.attributeType = null;
        this.attribute = attribute;
    }


    /**
     * Gets whether this node is a leaf - the answer is always true here.
     * 
     * @return true always
     */
    @Override
    public final boolean isLeaf()
    {
        return true;
    }


    /**
     * Gets the attributeType this leaf node is based on.
     * 
     * @return the attributeType asserted
     */
    public final AttributeType getAttributeType()
    {
        return attributeType;
    }


    /**
     * Gets the attribute this leaf node is based on.
     * 
     * @return the attribute asserted
     */
    public final String getAttribute()
    {
        return attribute;
    }


    /**
     * Sets the attributeType this leaf node is based on.
     * 
     * @param attributeType the attributeType that is asserted by this filter node
     */
    public void setAttributeType( AttributeType attributeType )
    {
        this.attributeType = attributeType;

        if ( attributeType != null )
        {
            attribute = attributeType.getName();
        }
    }


    /**
     * Sets the attribute this leaf node is based on.
     * 
     * @param attribute the attribute that is asserted by this filter node
     */
    public void setAttribute( String attribute )
    {
        this.attribute = attribute;
    }


    /**
     * @see ExprNode#accept(
     *FilterVisitor)
     * 
     * @param visitor the filter expression tree structure visitor
     * @return The modified element
     */
    @Override
    public final Object accept( FilterVisitor visitor )
    {
        if ( visitor.canVisit( this ) )
        {
            return visitor.visit( this );
        }
        else
        {
            return null;
        }
    }


    /**
     * Tells if this Node is Schema aware.
     * 
     * @return true if the Node is SchemaAware
     */
    @Override
public boolean isSchemaAware()
    {
        return attributeType != null;
    }
    
    
    /**
     * Escape a binary value into a String form that is accepted as a Filter
     */
    private static String escapeBytes( byte[] bytes )
    {
        // We have to escape all the bytes
        char[] chars = new char[bytes.length * 3];
        int pos = 0;
        
        for ( byte bb : bytes )
        {
            chars[pos++] = '\\';
            chars[pos++] = Strings.dumpHex( ( byte ) ( bb >> 4 ) );
            chars[pos++] = Strings.dumpHex( ( byte ) ( bb & 0x0F ) );
        }
        
        return new String( chars, 0, pos );
    }
    
    
    /**
     * Escape a String value into a String form that is accepted as a Filter
     */
    private static String escapeString( byte[] bytes )
    {
        StringBuilder sb = new StringBuilder( bytes.length );
        
        for ( byte b : bytes )
        {
            switch ( b )
            {
                case 0x20 : case 0x21 : case 0x22 : case 0x23 : case 0x24 : case 0x25 : case 0x26 : case 0x27 :
                    sb.append( ( char ) b );
                    break;
                    
                case 0x28 : 
                    // '('
                    sb.append( "\\28" );
                    break;
                    
                case 0x29 :
                    sb.append( "\\29" );
                    // ')'
                    break;
                    
                case 0x2A :
                    // '*'
                    sb.append( "\\2A" );
                    break;
                    
                case 0x2B : case 0x2C : case 0x2D : case 0x2E : case 0x2F : 
                case 0x30 : case 0x31 : case 0x32 : case 0x33 : case 0x34 : case 0x35 : case 0x36 : case 0x37 : 
                case 0x38 : case 0x39 : case 0x3A : case 0x3B : case 0x3C : case 0x3D : case 0x3E : case 0x3F : 
                case 0x40 : case 0x41 : case 0x42 : case 0x43 : case 0x44 : case 0x45 : case 0x46 : case 0x47 : 
                case 0x48 : case 0x49 : case 0x4A : case 0x4B : case 0x4C : case 0x4D : case 0x4E : case 0x4F : 
                case 0x50 : case 0x51 : case 0x52 : case 0x53 : case 0x54 : case 0x55 : case 0x56 : case 0x57 : 
                case 0x58 : case 0x59 : case 0x5A : case 0x5B : 
                    sb.append( ( char ) b );
                    break;

                case 0x5C :
                    // '\' 
                    sb.append( "\\5C" );
                    break;
                    
                case 0x5D : case 0x5E : case 0x5F : 
                case 0x60 : case 0x61 : case 0x62 : case 0x63 : case 0x64 : case 0x65 : case 0x66 : case 0x67 : 
                case 0x68 : case 0x69 : case 0x6A : case 0x6B : case 0x6C : case 0x6D : case 0x6E : case 0x6F : 
                case 0x70 : case 0x71 : case 0x72 : case 0x73 : case 0x74 : case 0x75 : case 0x76 : case 0x77 : 
                case 0x78 : case 0x79 : case 0x7A : case 0x7B : case 0x7C : case 0x7D : case 0x7E : case 0x7F :
                    sb.append( ( char ) b );
                    break;
                    
                default : 
                    // This is a binary value
                    return null;
            }
        }
        
        return sb.toString();
    }


    /**
     * Handles the escaping of special characters in LDAP search filter assertion values using the
     * &lt;valueencoding&gt; rule as described in
     * <a href="http://www.ietf.org/rfc/rfc4515.txt">RFC 4515</a>. Needed so that
     * {@link ExprNode#printToBuffer(StringBuffer)} results in a valid filter string that can be parsed
     * again (as a way of cloning filters).
     *
     * @param value Right hand side of "attrId=value" assertion occurring in an LDAP search filter.
     * @return Escaped version of <code>value</code>
     */
    protected static String escapeFilterValue( AttributeType attributeType, byte[] value )
    {
        if ( value == null )
        {
            return null;
        }

        if ( attributeType != null )
        {
            if ( attributeType.isHR() )
            {
                String result = escapeString( value );
                
                if ( result == null )
                {
                    return escapeBytes( value );
                }
                else
                {
                    return result;
                }
            }
            else
            {
                return escapeBytes( value );
            }
        }
        else
        {
            String result = escapeString( value );
            
            if ( result == null )
            {
                return escapeBytes( value );
            }
            else
            {
                return result;
            }
        }
    }


    /**
     * Handles the escaping of special characters in LDAP search filter assertion values using the
     * &lt;valueencoding&gt; rule as described in
     * <a href="http://www.ietf.org/rfc/rfc4515.txt">RFC 4515</a>. Needed so that
     * {@link ExprNode#printToBuffer(StringBuffer)} results in a valid filter string that can be parsed
     * again (as a way of cloning filters).
     *
     * @param value Right hand side of "attrId=value" assertion occurring in an LDAP search filter.
     * @return Escaped version of <code>value</code>
     */
    protected static String escapeFilterValue( String value )
    {
        if ( value == null )
        {
            return null;
        }
        
        StringBuilder sb = new StringBuilder( value.length() );
        
        for ( int i = 0; i < value.length(); i++ )
        {
            char c = value.charAt( i );
            
            switch ( c )
            {
                case 0x00:
                    sb.append( "\\00" );
                    break;
                    
                case '(' :
                    sb.append( "\\28" );
                    break;
                    
                case ')' :
                    sb.append( "\\29" );
                    break;
                    
                case '*' :
                    sb.append( "\\2A" );
                    break;
                    
                case '\\' :
                    sb.append( "\\5C" );
                    break;
                    
                default :
                    sb.append( c );
                    break;
                    
            }
        }
        
        return sb.toString();
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

        if ( attributeType != null )
        {
            h = h * 17 + attributeType.hashCode();
        }
        else
        {
            h = h * 17 + attribute.hashCode();
        }

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

        if ( !( other instanceof LeafNode ) )
        {
            return false;
        }

        LeafNode otherNode = ( LeafNode ) other;

        if ( other.getClass() != this.getClass() )
        {
            return false;
        }

        if ( attributeType != null )
        {
            return attributeType.equals( otherNode.getAttributeType() );
        }
        else
        {
            return attribute.equalsIgnoreCase( otherNode.getAttribute() );
        }
    }
}
