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
package org.apache.directory.api.ldap.model.message;


import java.util.Collection;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.name.Dn;


/**
 * Modify request protocol message used to alter the attributes and values of an
 * existing entry. Here's what <a href="https://www.ietf.org/rfc/rfc2255.txt">RFC 2255</a> says about it:
 * 
 * <pre>
 *  4.6. Modify Operation
 * 
 *   The Modify Operation allows a client to request that a modification
 *   of an entry be performed on its behalf by a server.  The Modify
 *   Request is defined as follows:
 * 
 *        ModifyRequest ::= [APPLICATION 6] SEQUENCE {
 *                object          LDAPDN,
 *                modification    SEQUENCE OF SEQUENCE {
 * 
 *                        operation       ENUMERATED {
 *                                                add     (0),
 *                                                delete  (1),
 *                                                replace (2) },
 *                        modification    AttributeTypeAndValues } }
 * 
 *        AttributeTypeAndValues ::= SEQUENCE {
 *                type    AttributeDescription,
 *                vals    SET OF AttributeValue }
 * 
 *   Parameters of the Modify Request are:
 * 
 *   - object: The object to be modified. The value of this field contains
 *     the Dn of the entry to be modified.  The server will not perform
 *     any alias dereferencing in determining the object to be modified.
 * 
 *   - modification: A list of modifications to be performed on the entry.
 *     The entire list of entry modifications MUST be performed
 *     in the order they are listed, as a single atomic operation.  While
 *     individual modifications may violate the directory schema, the
 *     resulting entry after the entire list of modifications is performed
 *     MUST conform to the requirements of the directory schema. The
 *     values that may be taken on by the 'operation' field in each
 *     modification construct have the following semantics respectively:
 *  
 * 
 *             add: add values listed to the given attribute, creating
 *             the attribute if necessary;
 * 
 *             delete: delete values listed from the given attribute,
 *             removing the entire attribute if no values are listed, or
 *             if all current values of the attribute are listed for
 *             deletion;
 * 
 *             replace: replace all existing values of the given attribute
 *             with the new values listed, creating the attribute if it
 *             did not already exist.  A replace with no value will delete
 *             the entire attribute if it exists, and is ignored if the
 *             attribute does not exist.
 *  </pre>
 * 
 *  Notice that we tried to leverage as much as we already can from the JNDI.
 *  Both the Names and ModificationItems are used here to make the API as easy
 *  as possible to understand.  We do not attempt here to write a JNDI provider
 *  which losses the explicit request type usage that we are looking for.  Also
 *  note that this library is both for the client side as well as the server side
 *  unlike the JNDI which is strictly for the client side.  From the JNDI we
 *  borrow good ideas and familiar signatures, interfaces and classes where we
 *  can.
 *  
 *  @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * 
 */
public interface ModifyRequest extends SingleReplyRequest, AbandonableRequest
{
    /**
     * Gets the distinguished name of the entry to be modified by this request.
     * This property represents the PDU's <b>object</b> field.
     * 
     * @return the Dn of the modified entry.
     */
    Dn getName();


    /**
     * Sets the distinguished name of the entry to be modified by this request.
     * This property represents the PDU's <b>object</b> field.
     * 
     * @param name the Dn of the modified entry.
     * @return The ModifyRequest instance
     */
    ModifyRequest setName( Dn name );


    /**
     * Gets an immutable Collection of modification items representing the
     * atomic changes to perform on the candidate entry to modify.
     * 
     * @return an immutable Collection of Modification instances.
     */
    Collection<Modification> getModifications();


    /**
     * Adds a ModificationItem to the set of modifications composing this modify
     * request.
     * 
     * @param mod a Modification to add.
     * @return The ModifyRequest instance
     */
    ModifyRequest addModification( Modification mod );


    /**
     * Removes a ModificationItem to the set of modifications composing this
     * modify request.
     * 
     * @param mod a Modification to remove.
     * @return The ModifyRequest instance
     */
    ModifyRequest removeModification( Modification mod );


    /**
     *
     * marks a given attribute for removal with the given
     * values from the target entry.
     *
     * @param attributeName name of the attribute to be removed
     * @param attributeValue values of the attribute
     * @return The ModifyRequest instance
     */
    ModifyRequest remove( String attributeName, String... attributeValue );


    /**
     * @see #remove(String, String...)
     * 
     * @param attributeName name of the attribute to be added
     * @param attributeValue values of the attribute
     * @return The ModifyRequest instance
     */
    ModifyRequest remove( String attributeName, byte[]... attributeValue );


    /**
     *
     * marks a given attribute for removal from the target entry.
     *
     * @param attr the attribute to be removed
     * @return The ModifyRequest instance
     */
    ModifyRequest remove( Attribute attr );


    /**
     *
     * marks a given attribute name for removal from the target entry.
     *
     * @param attributeName the attribute to be removed
     * @return The ModifyRequest instance
     */
    ModifyRequest remove( String attributeName );


    /**
     * Add a modification 
     * @param attr The attribute to be modified
     * @param modOp The operation
     * @return The ModifyRequest instance
     */
    ModifyRequest addModification( Attribute attr, ModificationOperation modOp );


    /**
     * marks a given attribute for addition in the target entry with the
     * given values.
     *
     * @param attributeName name of the attribute to be added
     * @param attributeValue values of the attribute
     * @return The ModifyRequest instance
     */
    ModifyRequest add( String attributeName, String... attributeValue );


    /**
     * @see #add(String, String...)
     * 
     * @param attributeName name of the attribute to be added
     * @param attributeValue values of the attribute
     * @return The ModifyRequest instance
     */
    ModifyRequest add( String attributeName, byte[]... attributeValue );


    /**
     * marks a given attribute for addition in the target entry.
     *
     * @param attr the attribute to be added
     * @return The ModifyRequest instance
     */
    ModifyRequest add( Attribute attr );


    /**
     * @see #replace(String, String...)
     * 
     * @param attributeName name of the attribute to be added
     * @return The ModifyRequest instance
     */
    ModifyRequest replace( String attributeName );


    /**
     * marks a given attribute for replacement with the given
     * values in the target entry.
     *
     * @param attributeName name of the attribute to be added
     * @param attributeValue values of the attribute
     * @return The ModifyRequest instance
     */
    ModifyRequest replace( String attributeName, String... attributeValue );


    /**
     * @see #replace(String, String...)
     * 
     * @param attributeName name of the attribute to be added
     * @param attributeValue values of the attribute
     * @return The ModifyRequest instance
     */
    ModifyRequest replace( String attributeName, byte[]... attributeValue );


    /**
     * marks a given attribute for replacement in the target entry.
     *
     * @param attr the attribute to be added
     * @return The ModifyRequest instance
     */
    ModifyRequest replace( Attribute attr );


    /**
     * {@inheritDoc}
     */
    @Override
    ModifyRequest setMessageId( int messageId );


    /**
     * {@inheritDoc}
     */
    @Override
    ModifyRequest addControl( Control control );


    /**
     * {@inheritDoc}
     */
    @Override
    ModifyRequest addAllControls( Control[] controls );


    /**
     * {@inheritDoc}
     */
    @Override
    ModifyRequest removeControl( Control control );
}
