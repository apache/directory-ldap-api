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
package org.apache.directory.api.ldap.model.entry;


import java.io.Externalizable;

import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.SyntaxChecker;


/**
 * A interface for wrapping attribute values stored into an EntryAttribute. These
 * values can be a String or a byte[].
 *
 * @param <T> The valye type
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface Value<T> extends Cloneable, Externalizable, Comparable<Value<T>>
{
    /** A flag used to tell if the value is HR in serialization */
    boolean STRING = true;

    /** A flag used to tell if the value is not HR in serialization */
    boolean BINARY = false;


    /**
     * Clone a Value
     * 
     * @return A cloned value
     */
    Value<T> clone();


    /**
     * Check if the contained value is null or not
     * 
     * @return <code>true</code> if the inner value is null.
     */
    boolean isNull();


    /**
     * Get the associated AttributeType
     * 
     * @return The AttributeType
     */
    AttributeType getAttributeType();


    /**
     * Check if the value is stored into an instance of the given
     * AttributeType, or one of its ascendant.
     * 
     * For instance, if the Value is associated with a CommonName,
     * checking for Name will match.
     * 
     * @param attributeType The AttributeType we are looking at
     * @return <code>true</code> if the value is associated with the given
     * attributeType or one of its ascendant
     */
    boolean isInstanceOf( AttributeType attributeType );


    /**
     * Get the User Provided value. It will return a copy, not a reference.
     *
     * @return a copy of the wrapped value
     */
    T getValue();


    /**
     * Get the wrapped value as a byte[]. If the original value
     * is binary, this method will return a copy of the wrapped byte[]
     *
     * @return the wrapped value as a byte[]
     */
    byte[] getBytes();


    /**
     * Get the user provided value as a String. If the original value
     * is binary, this method will return the value as if it was
     * an UTF-8 encoded String.
     *
     * @return the wrapped value as a String
     */
    String getString();


    /**
     * Gets a reference to the wrapped value.
     * 
     * Warning ! The value is not copied !!!
     *
     * @return a direct handle on the value that is wrapped
     */
    T getReference();


    /**
     * Tells if the value is schema aware or not.
     *
     * @return <code>true</code> if the value is sxhema aware
     */
    boolean isSchemaAware();


    /**
     * Uses the syntaxChecker associated with the attributeType to check if the
     * value is valid.
     * 
     * @param checker the SyntaxChecker to use to validate the value
     * @return <code>true</code> if the value is valid
     * @exception LdapInvalidAttributeValueException if the value cannot be validated
     */
    boolean isValid( SyntaxChecker checker ) throws LdapInvalidAttributeValueException;


    /**
     * Gets the normalized (canonical) representation for the wrapped string.
     * If the wrapped String is null, null is returned, otherwise the normalized
     * form is returned.  If the normalizedValue is null, then this method
     * will attempt to generate it from the wrapped value.
     *
     * @return gets the normalized value
     */
    T getNormValue();


    /**
     * Gets a reference to the the normalized (canonical) representation
     * for the wrapped value.
     *
     * @return gets a reference to the normalized value
     */
    T getNormReference();


    /**
     * Tells if the current value is Human Readable
     * 
     * @return <code>true</code> if the value is a String, <code>false</code> otherwise
     */
    boolean isHumanReadable();


    /**
     * @return The length of the interned value
     */
    int length();
    
    
    /**
     * Apply the AttributeType to this value. Note that this can't be done twice.
     *
     * @param attributeType The AttributeType to apply
     * @throws LdapInvalidAttributeValueException If we have some invalide value
     */
    void apply( AttributeType attributeType ) throws LdapInvalidAttributeValueException;
}
