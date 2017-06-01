/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.directory.api.ldap.model.entry;


import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectOutput;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.util.exception.NotImplementedException;


/**
 * A default implementation of a ServerEntry which should suite most
 * use cases.
 * 
 * This class is final, it should not be extended.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ImmutableEntry implements Entry
{
    /** Used for serialization */
    private static final long serialVersionUID = 2L;

    /** The wrapped Entry for this entry */
    private Entry entry;


    //-------------------------------------------------------------------------
    // Constructors
    //-------------------------------------------------------------------------
    /**
     * Creates a new instance of DefaultEntry. 
     * <p>
     * This entry <b>must</b> be initialized before being used !
     * </p>
     * @param entry the Entry to store
     */
    public ImmutableEntry( Entry entry )
    {
        this.entry = entry;
    }


    //-------------------------------------------------------------------------
    // Entry methods
    //-------------------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    public Entry add( AttributeType attributeType, byte[]... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot add an attribute : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry add( AttributeType attributeType, String... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot add an attribute : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry add( AttributeType attributeType, Value<?>... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot add an attribute : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    public Entry add( String upId, AttributeType attributeType, byte[]... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot add an attribute : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry add( String upId, AttributeType attributeType, Value<?>... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot add an attribute : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry add( String upId, AttributeType attributeType, String... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot add an attribute : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry add( Attribute... attributes ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot add an attribute : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    public Entry add( String upId, byte[]... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot add an attribute : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry add( String upId, String... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot add an attribute : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry add( String upId, Value<?>... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot add an attribute : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * Clone an entry. All the element are duplicated, so a modification on
     * the original object won't affect the cloned object, as a modification
     * on the cloned object has no impact on the original object
     */
    @Override
    public Entry clone()
    {
        return entry.clone();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Entry shallowClone()
    {
        return entry.shallowClone();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean contains( Attribute... attributes )
    {
        return entry.contains( attributes );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean containsAttribute( String... attributes )
    {
        return entry.containsAttribute( attributes );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean containsAttribute( AttributeType attributeType )
    {
        return entry.containsAttribute( attributeType );
    }


    /**
     * {@inheritDoc}
     */
    public boolean contains( AttributeType attributeType, byte[]... values )
    {
        return entry.contains( attributeType, values );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean contains( AttributeType attributeType, String... values )
    {
        return entry.contains( attributeType, values );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean contains( AttributeType attributeType, Value<?>... values )
    {
        return entry.contains( attributeType, values );
    }


    /**
     * {@inheritDoc}
     */
    public boolean contains( String upId, byte[]... values )
    {
        return entry.contains( upId, values );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean contains( String upId, String... values )
    {
        return entry.contains( upId, values );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean contains( String upId, Value<?>... values )
    {
        return entry.contains( upId, values );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Attribute get( String alias )
    {
        return entry.get( alias );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Attribute get( AttributeType attributeType )
    {
        return entry.get( attributeType );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<Attribute> getAttributes()
    {
        return entry.getAttributes();
    }


    /**
     * {@inheritDoc}
     */
    public Attribute put( String upId, byte[]... values )
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot put a value : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Attribute put( String upId, String... values )
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot put a value : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Attribute put( String upId, Value<?>... values )
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot put a value : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Attribute> put( Attribute... attributes ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot put a value : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    public Attribute put( AttributeType attributeType, byte[]... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot put a value : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Attribute put( AttributeType attributeType, String... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot put a value : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Attribute put( AttributeType attributeType, Value<?>... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot put a value : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    public Attribute put( String upId, AttributeType attributeType, byte[]... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot put a value : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Attribute put( String upId, AttributeType attributeType, String... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot put a value : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Attribute put( String upId, AttributeType attributeType, Value<?>... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot put a value : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<Attribute> remove( Attribute... attributes ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot remove a value : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    public boolean remove( AttributeType attributeType, byte[]... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot remove a value : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean remove( AttributeType attributeType, String... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot remove a value : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean remove( AttributeType attributeType, Value<?>... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot remove a value : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * <p>
     * Removes the attribute with the specified AttributeTypes. 
     * </p>
     * <p>
     * The removed attribute are returned by this method. 
     * </p>
     * <p>
     * If there is no attribute with the specified AttributeTypes,
     * the return value is <code>null</code>.
     * </p>
     *
     * @param attributes the AttributeTypes to be removed
     */
    @Override
    public void removeAttributes( AttributeType... attributes )
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot remove a value : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void removeAttributes( String... attributes )
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot remove a value : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * <p>
     * Removes the specified binary values from an attribute.
     * </p>
     * <p>
     * If at least one value is removed, this method returns <code>true</code>.
     * </p>
     * <p>
     * If there is no more value after having removed the values, the attribute
     * will be removed too.
     * </p>
     * <p>
     * If the attribute does not exist, nothing is done and the method returns 
     * <code>false</code>
     * </p> 
     *
     * @param upId The attribute ID  
     * @param values the values to be removed
     * @return <code>true</code> if at least a value is removed, <code>false</code>
     * if not all the values have been removed or if the attribute does not exist. 
     */
    public boolean remove( String upId, byte[]... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot remove a value : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * <p>
     * Removes the specified String values from an attribute.
     * </p>
     * <p>
     * If at least one value is removed, this method returns <code>true</code>.
     * </p>
     * <p>
     * If there is no more value after having removed the values, the attribute
     * will be removed too.
     * </p>
     * <p>
     * If the attribute does not exist, nothing is done and the method returns 
     * <code>false</code>
     * </p> 
     *
     * @param upId The attribute ID  
     * @param values the attributes to be removed
     * @return <code>true</code> if at least a value is removed, <code>false</code>
     * if not all the values have been removed or if the attribute does not exist. 
     */
    @Override
    public boolean remove( String upId, String... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot remove a value : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * <p>
     * Removes the specified values from an attribute.
     * </p>
     * <p>
     * If at least one value is removed, this method returns <code>true</code>.
     * </p>
     * <p>
     * If there is no more value after having removed the values, the attribute
     * will be removed too.
     * </p>
     * <p>
     * If the attribute does not exist, nothing is done and the method returns 
     * <code>false</code>
     * </p> 
     *
     * @param upId The attribute ID  
     * @param values the attributes to be removed
     * @return <code>true</code> if at least a value is removed, <code>false</code>
     * if not all the values have been removed or if the attribute does not exist. 
     */
    @Override
    public boolean remove( String upId, Value<?>... values ) throws LdapException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot remove a value : the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * Get this entry's Dn.
     *
     * @return The entry's Dn
     */
    @Override
    public Dn getDn()
    {
        return entry.getDn();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setDn( Dn dn )
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot rename the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setDn( String dn ) throws LdapInvalidDnException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot rename the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * Remove all the attributes for this entry. The Dn is not reset
     */
    @Override
    public void clear()
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot clear the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * Returns an enumeration containing the zero or more attributes in the
     * collection. The behavior of the enumeration is not specified if the
     * attribute collection is changed.
     *
     * @return an enumeration of all contained attributes
     */
    @Override
    public Iterator<Attribute> iterator()
    {
        return entry.iterator();
    }


    /**
     * Returns the number of attributes.
     *
     * @return the number of attributes
     */
    @Override
    public int size()
    {
        return entry.size();
    }


    /**
     * This is the place where we serialize entries, and all theirs
     * elements.
     * <br>
     * The structure used to store the entry is the following :
     * <ul>
     *   <li>
     *     <b>[Dn]</b> : If it's null, stores an empty Dn
     *   </li>
     *   <li>
     *     <b>[attributes number]</b> : the number of attributes.
     *   </li>
     *   <li>
     *     <b>[attribute]*</b> : each attribute, if we have some
     *   </li>
     * </ul>
     * 
     * {@inheritDoc} 
     */
    @Override
    public void writeExternal( ObjectOutput out ) throws IOException
    {
        entry.writeExternal( out );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void readExternal( ObjectInput in ) throws IOException, ClassNotFoundException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot read the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * Serialize an Entry.
     * 
     * The structure is the following :
     * <b>[a byte]</b> : if the Dn is empty 0 will be written else 1
     * <b>[Rdn]</b> : The entry's Rdn.
     * <b>[numberAttr]</b> : the bumber of attributes. Can be 0 
     * <b>[attribute's oid]*</b> : The attribute's OID to get back 
     * the attributeType on deserialization
     * <b>[Attribute]*</b> The attribute
     * 
     * @param out the buffer in which the data will be serialized
     * @throws IOException if the serialization failed
     */
    public void serialize( ObjectOutput out ) throws IOException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot serialize the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * Deserialize an entry. 
     * 
     * @param in The buffer containing the serialized serverEntry
     * @throws IOException if there was a problem when deserializing
     * @throws ClassNotFoundException if we can't deserialize an expected object
     */
    public void deserialize( ObjectInput in ) throws IOException, ClassNotFoundException
    {
        new Exception().printStackTrace();
        throw new NotImplementedException( "Cannot deserialize the entry " + entry.getDn() + " is immutable." );
    }


    /**
     * Get the hash code of this ClientEntry. The Attributes will be sorted
     * before the comparison can be done.
     *
     * @see java.lang.Object#hashCode()
     * @return the instance's hash code 
     */
    @Override
    public int hashCode()
    {
        return entry.hashCode();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasObjectClass( String... objectClasses )
    {
        return entry.hasObjectClass( objectClasses );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasObjectClass( Attribute... objectClasses )
    {
        return entry.hasObjectClass( objectClasses );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isSchemaAware()
    {
        return entry.isSchemaAware();
    }


    /**
     * @see Object#equals(Object)
     */
    @Override
    public boolean equals( Object o )
    {
        return entry.equals( o );
    }


    /**
     * @see Object#toString()
     */
    @Override
    public String toString()
    {
        return entry.toString();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString( String tabs )
    {
        return entry.toString( tabs );
    }
}
