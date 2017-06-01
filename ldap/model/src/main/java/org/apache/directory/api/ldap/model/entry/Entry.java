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


import java.io.Externalizable;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;


/**
 * This interface represent a LDAP entry. An LDAP entry contains :
 * <ul>
 *   <li> A distinguished name (Dn)</li>
 *   <li> A list of attributes</li>
 * </ul>
 * <p>
 * The available methods on this object are described in this interface.
 * <br>
 * This interface is used by the serverEntry and clientEntry interfaces.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface Entry extends Cloneable, Iterable<Attribute>, Externalizable
{
    /**
     * Remove all the attributes for this entry. The Dn is not reset
     */
    void clear();


    /**
     * Clone the current entry
     * 
     * @return the cloned entry
     */
    Entry clone();


    /**
     * Shallow Clone the current entry. We don't deep clone the attributes
     * 
     * @return A shallow clone of this entry
     */
    Entry shallowClone();


    /**
     * Get this entry's Dn.
     *
     * @return The entry's Dn
     */
    Dn getDn();


    /**
     * Tells if an entry as some specific ObjectClasses values
     * 
     * @param objectClasses The ObjectClasses we want to check
     * @return <code>true</code> if all the ObjectClasses value are present 
     * in the ObjectClass attribute
     */
    boolean hasObjectClass( String... objectClasses );


    /**
     * Tells if an entry has some specific ObjectClasses Attributes
     * 
     * @param objectClasses The ObjectClasses we want to check
     * @return <code>true</code> if the ObjectClasses Attribute are present 
     * in the ObjectClass attribute
     */
    boolean hasObjectClass( Attribute... objectClasses );


    /**
     * <p>
     * Returns the attribute with the specified alias. The return value
     * is <code>null</code> if no match is found.  
     * </p>
     * <p>An Attribute with an id different from the supplied alias may 
     * be returned: for example a call with 'cn' may in some implementations 
     * return an Attribute whose getId() field returns 'commonName'.
     * </p>
     *
     * @param alias an aliased name of the attribute identifier
     * @return the attribute associated with the alias
     */
    Attribute get( String alias );


    /**
     * Returns the attribute associated with an AttributeType
     * 
     * @param attributeType the AttributeType we are looking for
     * @return the associated attribute
     */
    Attribute get( AttributeType attributeType );


    /**
     * Gets all the attributes
     *
     * @return The combined set of all the attributes.
     */
    Collection<Attribute> getAttributes();


    /**
     * Set this entry's Dn.
     *
     * @param dn The Dn associated with this entry
     */
    void setDn( Dn dn );


    /**
     * Set this entry's Dn.
     *
     * @param dn The String Dn associated with this entry
     * @throws LdapInvalidDnException if the provided Dn is invalid
     */
    void setDn( String dn ) throws LdapInvalidDnException;


    /**
     * Returns an iterator on the attributes for this entry.
     *
     * @return an iterator on top of all contained attributes
     */
    @Override
    Iterator<Attribute> iterator();


    /**
     * Add some Attributes to the current Entry.
     *
     * @param attributes The attributes to add
     * @return the modified entry
     * @throws LdapException If we can't add any of the attributes
     */
    Entry add( Attribute... attributes ) throws LdapException;


    /**
     * <p>
     * Add an attribute (represented by its AttributeType and some binary values) into an 
     * entry.
     * </p>
     * <p> 
     * If we already have an attribute with the same values, the duplicated values 
     * are not added (duplicated values are not allowed)
     * </p>
     * <p>
     * If the value cannot be added, or if the AttributeType is null or invalid, 
     * a LdapException is thrown.
     * </p>
     *
     * @param attributeType The attribute Type.
     * @param values The list of binary values to inject. It can be empty.
     * @return the modified entry
     * @throws LdapException If the attribute does not exist
     */
    Entry add( AttributeType attributeType, byte[]... values ) throws LdapException;


    /**
     * <p>
     * Add an attribute (represented by its AttributeType and some String values) into an 
     * entry.
     * </p>
     * <p> 
     * If we already have an attribute with the same values, the duplicated values 
     * are not added (duplicated values are not allowed)
     * </p>
     * <p> 
     * If the value cannot be added, or if the AttributeType is null or invalid, 
     * a LdapException is thrown.
     * </p>
     * 
     * @param attributeType The attribute Type
     * @param values The list of binary values to inject. It can be empty
     * @return the modified entry
     * @throws org.apache.directory.api.ldap.model.exception.LdapException If the attribute does not exist
     */
    Entry add( AttributeType attributeType, String... values ) throws LdapException;


    /**
     * <p>
     * Add an attribute (represented by its AttributeType and some values) into an 
     * entry.
     * </p>
     * <p> 
     * If we already have an attribute with the same values, the duplicated values 
     * are not added (duplicated values are not allowed)
     * </p>
     * <p>
     * If the value cannot be added, or if the AttributeType is null or invalid, 
     * a LdapException is thrown.
     * </p>
     *
     * @param attributeType The attribute Type
     * @param values The list of binary values to inject. It can be empty
     * @return the modified entry
     * @throws LdapException If the attribute does not exist
     */
    Entry add( AttributeType attributeType, Value<?>... values ) throws LdapException;


    /**
     * <p>
     * Add an attribute (represented by its AttributeType and some binary values) into an 
     * entry. Set the User Provider ID at the same time
     * </p>
     * <p> 
     * If we already have an attribute with the same values, the duplicated values 
     * are not added (duplicated values are not allowed)
     * </p>
     * <p>
     * If the value cannot be added, or if the AttributeType is null or invalid, 
     * a LdapException is thrown.
     * </p>
     *
     * @param upId The user provided ID for the added AttributeType
     * @param attributeType The attribute Type.
     * @param values The list of binary values to add. It can be empty.
     * @return the modified entry
     * @throws LdapException If the attribute does not exist
     */
    Entry add( String upId, AttributeType attributeType, byte[]... values ) throws LdapException;


    /**
     * <p>
     * Add an attribute (represented by its AttributeType and some String values) into an 
     * entry. Set the User Provider ID at the same time
     * </p>
     * <p> 
     * If we already have an attribute with the same values, the duplicated values 
     * are not added (duplicated values are not allowed)
     * </p>
     * <p>
     * If the value cannot be added, or if the AttributeType is null or invalid, 
     * a LdapException is thrown.
     * </p>
     *
     * @param upId The user provided ID for the added AttributeType
     * @param attributeType The attribute Type.
     * @param values The list of String values to add. It can be empty.
     * @return the modified entry
     * @throws LdapException If the attribute does not exist
     */
    Entry add( String upId, AttributeType attributeType, String... values ) throws LdapException;


    /**
     * <p>
     * Add an attribute (represented by its AttributeType and some values) into an 
     * entry. Set the User Provider ID at the same time
     * </p>
     * <p> 
     * If we already have an attribute with the same values, nothing is done 
     * (duplicated values are not allowed)
     * </p>
     * <p>
     * If the value cannot be added, or if the AttributeType is null or invalid, 
     * a LdapException is thrown.
     * </p>
     *
     * @param upId The user provided ID for the added AttributeType
     * @param attributeType The attribute Type.
     * @param values The list of values to add. It can be empty.
     * @return the modified entry
     * @throws LdapException If the attribute does not exist
     */
    Entry add( String upId, AttributeType attributeType, Value<?>... values ) throws LdapException;


    /**
     * Add some String values to the current Entry.
     *
     * @param upId The user provided ID of the attribute we want to add 
     * some values to
     * @param values The list of String values to add
     * @return the modified entry
     * @throws LdapException If we can't add any of the values
     */
    Entry add( String upId, String... values ) throws LdapException;


    /**
     * Add some binary values to the current Entry.
     *
     * @param upId The user provided ID of the attribute we want to add 
     * some values to
     * @param values The list of binary values to add
     * @return the modified entry
     * @throws LdapException If we can't add any of the values
     */
    Entry add( String upId, byte[]... values ) throws LdapException;


    /**
     * Add some Values to the current Entry.
     *
     * @param upId The user provided ID of the attribute we want to add 
     * some values to
     * @param values The list of Values to add
     * @return the modified entry
     * @throws LdapException If we can't add any of the values
     */
    Entry add( String upId, Value<?>... values ) throws LdapException;


    /**
     * <p>
     * Places attributes in the attribute collection. 
     * </p>
     * <p>If there is already an attribute with the same ID as any of the 
     * new attributes, the old ones are removed from the collection and 
     * are returned by this method. If there was no attribute with the 
     * same ID the return value is <code>null</code>.
     *</p>
     *
     * @param attributes the attributes to be put
     * @return the old attributes with the same OID, if exist; otherwise <code>null</code>
     * @exception LdapException if the operation fails
     */
    List<Attribute> put( Attribute... attributes ) throws LdapException;


    /**
     * <p>
     * Places a new attribute with the supplied AttributeType and binary values 
     * into the attribute collection. 
     * </p>
     * <p>
     * If there is already an attribute with the same AttributeType, the old
     * one is removed from the collection and is returned by this method. 
     * </p>
     * <p>
     * This method provides a mechanism to put an attribute with a
     * <code>null</code> value: the value may be <code>null</code>.
     *
     * @param attributeType the type of the new attribute to be put
     * @param values the binary values of the new attribute to be put
     * @return the old attribute with the same identifier, if exists; otherwise
     * <code>null</code>
     * @throws org.apache.directory.api.ldap.model.exception.LdapException if there are failures
     */
    Attribute put( AttributeType attributeType, byte[]... values ) throws LdapException;


    /**
     * <p>
     * Places a new attribute with the supplied AttributeType and String values 
     * into the attribute collection. 
     * </p>
     * <p>
     * If there is already an attribute with the same AttributeType, the old
     * one is removed from the collection and is returned by this method. 
     * </p>
     * <p>
     * This method provides a mechanism to put an attribute with a
     * <code>null</code> value: the value may be <code>null</code>.
     *
     * @param attributeType the type of the new attribute to be put
     * @param values the String values of the new attribute to be put
     * @return the old attribute with the same identifier, if exists; otherwise
     * <code>null</code>
     * @throws org.apache.directory.api.ldap.model.exception.LdapException if there are failures
     */
    Attribute put( AttributeType attributeType, String... values ) throws LdapException;


    /**
     * <p>
     * Places a new attribute with the supplied AttributeType and some values 
     * into the attribute collection. 
     * </p>
     * <p>
     * If there is already an attribute with the same AttributeType, the old
     * one is removed from the collection and is returned by this method. 
     * </p>
     * <p>
     * This method provides a mechanism to put an attribute with a
     * <code>null</code> value: the value may be <code>null</code>.
     *
     * @param attributeType the type of the new attribute to be put
     * @param values the values of the new attribute to be put
     * @return the old attribute with the same identifier, if exists; otherwise
     * <code>null</code>
     * @throws LdapException if there are failures
     */
    Attribute put( AttributeType attributeType, Value<?>... values ) throws LdapException;


    /**
     * <p>
     * Places a new attribute with the supplied AttributeType and some binary values 
     * into the attribute collection. 
     * </p>
     * <p>
     * The given User provided ID will be used for this new AttributeEntry.
     * </p>
     * <p>
     * If there is already an attribute with the same AttributeType, the old
     * one is removed from the collection and is returned by this method. 
     * </p>
     * <p>
     * This method provides a mechanism to put an attribute with a
     * <code>null</code> value: the value may be <code>null</code>.
     *
     * @param upId The User Provided ID to be stored into the AttributeEntry
     * @param attributeType the type of the new attribute to be put
     * @param values the binary values of the new attribute to be put
     * @return the old attribute with the same identifier, if exists; otherwise
     * <code>null</code>
     * @throws LdapException if there are failures.
     */
    Attribute put( String upId, AttributeType attributeType, byte[]... values ) throws LdapException;


    /**
     * <p>
     * Places a new attribute with the supplied AttributeType and some String values 
     * into the attribute collection. 
     * </p>
     * <p>
     * The given User provided ID will be used for this new AttributeEntry.
     * </p>
     * <p>
     * If there is already an attribute with the same AttributeType, the old
     * one is removed from the collection and is returned by this method. 
     * </p>
     * <p>
     * This method provides a mechanism to put an attribute with a
     * <code>null</code> value: the value may be <code>null</code>.
     *
     * @param upId The User Provided ID to be stored into the AttributeEntry
     * @param attributeType the type of the new attribute to be put
     * @param values the String values of the new attribute to be put
     * @return the old attribute with the same identifier, if exists; otherwise
     * <code>null</code>
     * @throws org.apache.directory.api.ldap.model.exception.LdapException if there are failures.
     */
    Attribute put( String upId, AttributeType attributeType, String... values ) throws LdapException;


    /**
     * <p>
     * Places a new attribute with the supplied AttributeType and some values 
     * into the attribute collection. 
     * </p>
     * <p>
     * The given User provided ID will be used for this new AttributeEntry.
     * </p>
     * <p>
     * If there is already an attribute with the same AttributeType, the old
     * one is removed from the collection and is returned by this method. 
     * </p>
     * <p>
     * This method provides a mechanism to put an attribute with a
     * <code>null</code> value: the value may be <code>null</code>.
     *
     * @param upId The User Provided ID to be stored into the AttributeEntry
     * @param attributeType the type of the new attribute to be put
     * @param values the values of the new attribute to be put
     * @return the old attribute with the same identifier, if exists; otherwise
     * <code>null</code>
     * @throws LdapException if there are failures.
     */
    Attribute put( String upId, AttributeType attributeType, Value<?>... values ) throws LdapException;


    /**
     * <p>
     * Put an attribute (represented by its ID and some binary values) into an entry. 
     * </p>
     * <p> 
     * If the attribute already exists, the previous attribute will be 
     * replaced and returned.
     * </p>
     *
     * @param upId The attribute ID
     * @param values The list of binary values to put. It can be empty.
     * @return The replaced attribute
     */
    Attribute put( String upId, byte[]... values );


    /**
     * <p>
     * Put an attribute (represented by its ID and some String values) into an entry. 
     * </p>
     * <p> 
     * If the attribute already exists, the previous attribute will be 
     * replaced and returned.
     * </p>
     *
     * @param upId The attribute ID
     * @param values The list of String values to put. It can be empty.
     * @return The replaced attribute
     */
    Attribute put( String upId, String... values );


    /**
     * <p>
     * Put an attribute (represented by its ID and some values) into an entry. 
     * </p>
     * <p> 
     * If the attribute already exists, the previous attribute will be 
     * replaced and returned.
     * </p>
     *
     * @param upId The attribute ID
     * @param values The list of values to put. It can be empty.
     * @return The replaced attribute
     */
    Attribute put( String upId, Value<?>... values );


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
     * @param attributeType The attribute type  
     * @param values the values to be removed
     * @return <code>true</code> if at least a value is removed, <code>false</code>
     * if not all the values have been removed or if the attribute does not exist. 
     * @throws LdapException If the removal failed 
     */
    boolean remove( AttributeType attributeType, byte[]... values ) throws LdapException;


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
     * @param attributeType The attribute type  
     * @param values the values to be removed
     * @return <code>true</code> if at least a value is removed, <code>false</code>
     * if not all the values have been removed or if the attribute does not exist. 
     * @throws LdapException If the removal failed 
     */
    boolean remove( AttributeType attributeType, String... values ) throws LdapException;


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
     * @param attributeType The attribute type  
     * @param values the values to be removed
     * @return <code>true</code> if at least a value is removed, <code>false</code>
     * if not all the values have been removed or if the attribute does not exist. 
     * @throws LdapException If the removal failed 
     */
    boolean remove( AttributeType attributeType, Value<?>... values ) throws LdapException;


    /**
     * Removes the specified attributes. The removed attributes are
     * returned by this method. If there were no attribute the return value
     * is <code>null</code>.
     *
     * @param attributes the attributes to be removed
     * @return the removed attribute, if exists; otherwise <code>null</code>
     * @throws LdapException If the removal failed 
     */
    List<Attribute> remove( Attribute... attributes ) throws LdapException;


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
    void removeAttributes( AttributeType... attributes );


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
     * @param values the attribute's values to be removed
     * @return <code>true</code> if at least a value is removed, <code>false</code>
     * if not all the values have been removed or if the attribute does not exist. 
     * @throws LdapException If the removal failed 
     */
    boolean remove( String upId, byte[]... values ) throws LdapException;


    /**
     * <p>
     * Removes the specified String values from an attribute.
     * </p>
     * <p>
     * If at least one value is removed, this method returns <code>true</code>.
     * </p>
     * <p>
     * If there is no more value after havong removed the values, the attribute
     * will be removed too.
     * </p>
     * <p>
     * If the attribute does not exist, nothing is done and the method returns 
     * <code>false</code>
     * </p> 
     *
     * @param upId The attribute ID  
     * @param values the attribute's values to be removed
     * @return <code>true</code> if at least a value is removed, <code>false</code>
     * if no values have been removed or if the attribute does not exist.
     * @throws LdapException If the removal failed 
     */
    boolean remove( String upId, String... values ) throws LdapException;


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
     * @param values the attribute's values to be removed
     * @return <code>true</code> if at least a value is removed, <code>false</code>
     * if not all the values have been removed or if the attribute does not exist. 
     * @throws LdapException if the attribute does not exists
     */
    boolean remove( String upId, Value<?>... values ) throws LdapException;


    /**
      * <p>
      * Removes the attribute with the specified alias. 
      * </p>
      * <p>
      * The removed attribute are returned by this method. 
      * </p>
      * <p>
      * If there is no attribute with the specified alias,
      * the return value is <code>null</code>.
      * </p>
      *
      * @param attributes an aliased name of the attribute to be removed
      */
    void removeAttributes( String... attributes );


    // -----------------------------------------------------------------------
    // Container (contains/get/put/remove) Methods
    // -----------------------------------------------------------------------
    /**
     * Checks if an entry contains an attribute with some given binary values.
     *
     * @param attributeType The Attribute we are looking for.
     * @param values The searched binary values.
     * @return <code>true</code> if all the values are found within the attribute,
     * <code>false</code> otherwise, or if the attributes does not exist.
     */
    boolean contains( AttributeType attributeType, byte[]... values );


    /**
     * Checks if an entry contains an attribute with some given String values.
     *
     * @param attributeType The Attribute we are looking for.
     * @param values The searched String values.
     * @return <code>true</code> if all the values are found within the attribute,
     * <code>false</code> otherwise, or if the attributes does not exist.
     */
    boolean contains( AttributeType attributeType, String... values );


    /**
     * Checks if an entry contains an attribute with some given binary values.
     *
     * @param attributeType The Attribute we are looking for.
     * @param values The searched values.
     * @return <code>true</code> if all the values are found within the attribute,
     * <code>false</code> otherwise, or if the attributes does not exist.
     */
    boolean contains( AttributeType attributeType, Value<?>... values );


    /**
     * Checks if an entry contains a specific AttributeType.
     *
     * @param attributeType The AttributeType to look for.
     * @return <code>true</code> if the attribute is found within the entry.
     */
    boolean containsAttribute( AttributeType attributeType );


    /**
     * <p>
     * Checks if an entry contains a list of attributes.
     * </p>
     * <p>
     * If the list is null or empty, this method will return <code>true</code>
     * if the entry has no attribute, <code>false</code> otherwise.
     * </p>
     *
     * @param attributes The Attributes to look for
     * @return <code>true</code> if all the attributes are found within 
     * the entry, <code>false</code> if at least one of them is not present.
     */
    boolean contains( Attribute... attributes );


    /**
     * Checks if an entry contains an attribute with some binary values.
     *
     * @param upId The Attribute we are looking for.
     * @param values The searched values.
     * @return <code>true</code> if all the values are found within the attribute,
     * false if at least one value is not present or if the ID is not valid. 
     */
    boolean contains( String upId, byte[]... values );


    /**
     * Checks if an entry contains an attribute with some String values.
     *
     * @param upId The Attribute we are looking for.
     * @param values The searched values.
     * @return <code>true</code> if all the values are found within the attribute,
     * false if at least one value is not present or if the ID is not valid. 
     */
    boolean contains( String upId, String... values );


    /**
     * Checks if an entry contains an attribute with some values.
     *
     * @param upId The Attribute we are looking for.
     * @param values The searched values.
     * @return <code>true</code> if all the values are found within the attribute,
     * false if at least one value is not present or if the ID is not valid. 
     */
    boolean contains( String upId, Value<?>... values );


    /**
     * Checks if an entry contains some specific attributes.
     *
     * @param attributes The Attributes to look for.
     * @return <code>true</code> if the attributes are all found within the entry.
     */
    boolean containsAttribute( String... attributes );


    /**
     * Returns the number of attributes.
     *
     * @return the number of attributes
     */
    int size();


    /**
     * Tells if the Entry is schema aware
     * @return true if the Entry is schema aware
     */
    boolean isSchemaAware();


    /**
     * A pretty-pinter for Entries
     * 
     * @param tabs The tabs to add before any output
     * @return The pretty-printed entry
     */
    String toString( String tabs );
}
