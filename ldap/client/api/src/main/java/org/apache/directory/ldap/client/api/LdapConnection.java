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
package org.apache.directory.ldap.client.api;


import java.io.Closeable;
import java.io.IOException;
import java.util.List;

import org.apache.directory.api.asn1.util.Oid;
import org.apache.directory.api.ldap.codec.api.BinaryAttributeDetector;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.AbandonRequest;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.AddResponse;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.CompareRequest;
import org.apache.directory.api.ldap.model.message.CompareResponse;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.DeleteRequest;
import org.apache.directory.api.ldap.model.message.DeleteResponse;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.message.ModifyDnRequest;
import org.apache.directory.api.ldap.model.message.ModifyDnResponse;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyResponse;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;


// TODO: all the SASL bind methods are not declared in this interface, but implemented in LdapNetworkConnection. Is that intended?
// TODO: why does connect() return a boolean? What is the difference between false and an Exception?
// TODO: describe better which type of LdapException are thrown in which case?
// TODO: does method getCodecService() belong into the interface? It returns a LdapApiService, should it be renamed?
// TODO: does method doesFutureExistFor() belong into the interface? Move to LdapAsyncConnection?

/**
 * The root interface for all the LDAP connection implementations. All operations defined in this interface are blocking (synchronous).
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface LdapConnection extends Closeable
{
    /**
     * Check if the connection is established
     *
     * @return <code>true</code> if the connection is established
     */
    boolean isConnected();


    /**
     * Check if the connection is authenticated.
     *
     * @return <code>true</code> if the connection is authenticated
     */
    boolean isAuthenticated();


    /**
     * Connect to the remote LDAP server.
     *
     * @return <code>true</code> if the connection is established, false otherwise
     * @throws LdapException if some error occurred
     */
    boolean connect() throws LdapException;


    /**
     * Disconnect from the remote LDAP server.
     *
     * @throws IOException if some I/O error occurs
     */
    @Override
    void close() throws IOException;


    //------------------------ The LDAP operations ------------------------//
    // Add operations                                                      //
    //---------------------------------------------------------------------//
    /**
     * Add an entry to the server.
     *
     * @param entry The entry to add
     * @throws LdapException if some error occurred
     */
    void add( Entry entry ) throws LdapException;


    /**
     * Add an entry present in the {@link AddRequest} to the server.
     *
     * @param addRequest the request object containing an entry and controls (if any)
     * @return the add operation's response
     * @throws LdapException if some error occurred
     */
    AddResponse add( AddRequest addRequest ) throws LdapException;


    /**
     * Abandons a request submitted to the server for performing a particular operation.
     *
     * The abandonRequest is always non-blocking, because no response is expected
     *
     * @param messageId the ID of the request message sent to the server
     */
    void abandon( int messageId );


    /**
     * An abandon request essentially with the request message ID of the operation to be canceled
     * and/or potentially some controls and timeout (the controls and timeout are not mandatory).
     *
     * The abandonRequest is always non-blocking, because no response is expected.
     *
     * @param abandonRequest the abandon operation's request
     */
    void abandon( AbandonRequest abandonRequest );


    /**
     * Bind on a server, using the {@link LdapConnectionConfig} information of this connection.
     *
     * @throws LdapException if some error occurred
     */
    void bind() throws LdapException;


    /**
     * Anonymous bind on a server.
     *
     * @throws LdapException if some error occurred
     */
    void anonymousBind() throws LdapException;


    /**
     * Unauthenticated authentication bind on a server.
     *
     * @param name The name used to authenticate the user. It must be a
     * valid distinguished name.
     * @throws LdapException if some error occurred
     */
    void bind( String name ) throws LdapException;


    /**
     * Simple bind on a server.
     *
     * @param name The name used to authenticate the user. It must be a
     * valid distinguished name.
     * @param credentials The password, it can't be <code>null</code>
     * @throws LdapException if some error occurred
     */
    void bind( String name, String credentials ) throws LdapException;


    /**
     * SASL PLAIN Bind on a server.
     *
     * @param authcid The Authentication identity
     * @param credentials The password, it can't be null
     * @return The BindResponse LdapResponse
     * @throws LdapException if some error occurred
     */
    // Not yet available on the CoreConnection
    //BindResponse bindSaslPlain( String authcid, String credentials ) throws LdapException;

    /**
     * SASL PLAIN Bind on a server.
     *
     * @param authzid The Authorization identity
     * @param authcid The Authentication identity
     * @param credentials The password. It can't be null
     * @return The BindResponse LdapResponse
     * @throws LdapException if some error occurred
     */
    // Not yet available on the CoreConnection
    //BindResponse bindSaslPlain( String authzid, String authcid, String credentials ) throws LdapException;

    /**
     * Unauthenticated authentication bind on a server.
     *
     * @param name The name used to authenticate the user.
     * @throws LdapException if some error occurred
     */
    void bind( Dn name ) throws LdapException;


    /**
     * Simple bind on a server.
     *
     * @param name The name used to authenticate the user.
     * @param credentials The password, it can't be null
     * @throws LdapException if some error occurred
     */
    void bind( Dn name, String credentials ) throws LdapException;


    /**
     * Bind to the server using a bind request object.
     *
     * @param bindRequest The bind request object containing all the needed parameters
     * @return A {@link BindResponse} containing the result
     * @throws LdapException if some error occurred
     */
    BindResponse bind( BindRequest bindRequest ) throws LdapException;


    /**
     * Do a search, on the base object, using the given filter and scope. The
     * SearchRequest parameters default to
     * <ul>
     * <li> DerefAlias : ALWAYS
     * <li> SizeLimit : none
     * <li> TimeLimit : none
     * <li> TypesOnly : false
     * </ul>
     * 
     * @param baseDn The base for the search. It must be a valid distinguished name and can't be emtpy
     * @param filter The filter to use for this search. It can't be empty
     * @param scope The search scope : OBJECT, ONELEVEL or SUBTREE
     * @param attributes The attributes to use for this search
     * @return An {@link EntryCursor} on the result.
     * @throws LdapException if some error occurred
     */
    EntryCursor search( Dn baseDn, String filter, SearchScope scope, String... attributes )
        throws LdapException;


    /**
     * Do a search, on the base object, using the given filter and scope. The
     * SearchRequest parameters default to
     * <ul>
     * <li> DerefAlias : ALWAYS
     * <li> SizeLimit : none
     * <li> TimeLimit : none
     * <li> TypesOnly : false
     * </ul>
     *
     * @param baseDn The base for the search. It must be a valid distinguished name, and can't be emtpy
     * @param filter The filter to use for this search. It can't be empty
     * @param scope The search scope : OBJECT, ONELEVEL or SUBTREE
     * @param attributes The attributes to use for this search
     * @return An {@link EntryCursor} on the result.
     * @throws LdapException if some error occurred
     */
    EntryCursor search( String baseDn, String filter, SearchScope scope, String... attributes )
        throws LdapException;


    /**
     * Performs search using a search request object.
     *
     * @param searchRequest The search request object containing all the needed information
     * @return a search cursor on the result.
     * @throws LdapException if some error occurred
     */
    SearchCursor search( SearchRequest searchRequest ) throws LdapException;


    //------------------------ The LDAP operations ------------------------//
    // Unbind operations                                                   //
    //---------------------------------------------------------------------//
    /**
     * UnBind from a server. This is a request which expects no response.
     * 
     * @throws LdapException if some error occurred
     */
    void unBind() throws LdapException;


    /**
     * Set the timeout for the responses. We won't wait longer than this
     * value.
     *
     * @param timeOut The timeout, in milliseconds
     */
    void setTimeOut( long timeOut );


    /**
     * Applies all the modifications to the entry specified by its distinguished name.
     *
     * @param dn The entry's distinguished name
     * @param modifications The list of modifications to be applied
     * @throws LdapException in case of modify operation failure or timeout happens
     */
    void modify( Dn dn, Modification... modifications ) throws LdapException;


    /**
     * Applies all the modifications to the entry specified by its distinguished name.
     *
     * @param dn The entry's distinguished name, it must be a valid distinguished name.
     * @param modifications The list of modifications to be applied
     * @throws LdapException in case of modify operation failure or timeout happens
     */
    void modify( String dn, Modification... modifications ) throws LdapException;


    /**
     * Modifies all the attributes present in the entry by applying the same operation.
     *
     * @param entry the entry with the attributes to be modified
     * @param modOp the operation to be applied on all the attributes of the above entry
     * @throws LdapException in case of modify operation failure or timeout happens
     */
    void modify( Entry entry, ModificationOperation modOp ) throws LdapException;


    /**
     * Performs an modify operation based on the modifications present in
     * the modify request.
     *
     * @param modRequest the modify request object
     * @return the modify operation's response
     * @throws LdapException in case of modify operation failure or timeout happens
     */
    ModifyResponse modify( ModifyRequest modRequest ) throws LdapException;


    /**
     * Renames the given entryDn with new relative distinguished name and deletes the 
     * old relative distinguished name.
     *
     * @param entryDn the target distinguished name.
     * @param newRdn new relative distinguished name for the target distinguished name.
     * @throws LdapException if some error occurred
     * @see #rename(String, String, boolean)
     */
    void rename( String entryDn, String newRdn ) throws LdapException;


    /**
     * Renames the given entryDn with new relative distinguished name and deletes the 
     * old relative distinguished name.
     *
     * @param entryDn the target distinguished name.
     * @param newRdn new relative distinguished name for the target distinguished name.
     * @throws LdapException if some error occurred
     * @see #rename(Dn, Rdn, boolean)
     */
    void rename( Dn entryDn, Rdn newRdn ) throws LdapException;


    /**
     * Renames the given entryDn with new relative distinguished name and deletes the 
     * old relative distinguished name if deleteOldRdn is set to true.
     *
     * @param entryDn the target distinguished name.
     * @param newRdn new relative distinguished name for the target distinguished name.
     * @param deleteOldRdn flag to indicate whether to delete the old relative distinguished name
     * @throws LdapException if some error occurred
     * @see #rename(Dn, Rdn, boolean)
     */
    void rename( String entryDn, String newRdn, boolean deleteOldRdn ) throws LdapException;


    /**
     * Renames the given entryDn with new relative distinguished name and deletes the 
     * old relative distinguished name if deleteOldRdn is set to true.
     *
     * @param entryDn the target distinguished name.
     * @param newRdn new relative distinguished name for the target distinguished name.
     * @param deleteOldRdn flag to indicate whether to delete the old relative distinguished name
     * @throws LdapException if some error occurred
     */
    void rename( Dn entryDn, Rdn newRdn, boolean deleteOldRdn ) throws LdapException;


    /**
     * Moves the given entry distinguished name under the new superior distinguished name.
     *
     * @param entryDn the distinguished name of the target entry
     * @param newSuperiorDn distinguished name of the new parent/superior
     * @throws LdapException if some error occurred
     * @see #move(Dn, Dn)
     */
    void move( String entryDn, String newSuperiorDn ) throws LdapException;


    /**
     * Moves the given entry distinguished name under the new superior distinguished name.
     *
     * @param entryDn the distinguished name of the target entry
     * @param newSuperiorDn distinguished name of the new parent/superior
     * @throws LdapException if some error occurred
     */
    void move( Dn entryDn, Dn newSuperiorDn ) throws LdapException;


    /**
     * Moves and renames the given entryDn. The old relative distinguished name will be deleted.
     *
     * @param entryDn The original entry distinguished name.
     * @param newDn The new entry distinguished name.
     * @throws LdapException if some error occurred
     * @see #moveAndRename(Dn, Dn, boolean)
     */
    void moveAndRename( Dn entryDn, Dn newDn ) throws LdapException;


    /**
     * Moves and renames the given entry distinguished name. The old relative 
     * distinguished name will be deleted
     *
     * @param entryDn The original entry distinguished name.
     * @param newDn The new entry distinguished name.
     * @throws LdapException if some error occurred
     * @see #moveAndRename(Dn, Dn, boolean)
     */
    void moveAndRename( String entryDn, String newDn ) throws LdapException;


    /**
     * Moves and renames the given entryDn. The old relative distinguished name will be deleted if requested.
     *
     * @param entryDn The original entry distinguished name.
     * @param newDn The new entry distinguished name.
     * @param deleteOldRdn Tells if the old relative distinguished name must be removed
     * @throws LdapException if some error occurred
     */
    void moveAndRename( Dn entryDn, Dn newDn, boolean deleteOldRdn ) throws LdapException;


    /**
     * Moves and renames the given entryDn. The old relative distinguished name will be deleted if requested.
     *
     * @param entryDn The original entry distinguished name.
     * @param newDn The new entry distinguished name.
     * @param deleteOldRdn Tells if the old relative distinguished name must be removed
     * @throws LdapException if some error occurred
     */
    void moveAndRename( String entryDn, String newDn, boolean deleteOldRdn )
        throws LdapException;


    /**
     * Performs the modifyDn operation based on the given request object.
     *
     * @param modDnRequest the request object
     * @return modifyDn operation's response
     * @throws LdapException if some error occurred
     */
    ModifyDnResponse modifyDn( ModifyDnRequest modDnRequest ) throws LdapException;


    /**
     * Deletes the entry with the given distinguished name.
     *
     * @param dn the target entry's distinguished name, it must be a valid distinguished name.
     * @throws LdapException If the distinguished name is not valid or if the deletion failed
     */
    void delete( String dn ) throws LdapException;


    /**
     * Deletes the entry with the given distinguished name.
     *
     * @param dn the target entry's distinguished name
     * @throws LdapException If the distinguished name is not valid or if the deletion failed
     */
    void delete( Dn dn ) throws LdapException;


    /**
     * Performs a delete operation based on the delete request object.
     *
     * @param deleteRequest the delete operation's request
     * @return delete operation's response
     * @throws LdapException If the distinguished name is not valid or if the deletion failed
     */
    DeleteResponse delete( DeleteRequest deleteRequest ) throws LdapException;


    /**
     * Compares whether a given attribute's value matches that of the
     * existing value of the attribute present in the entry with the given distinguished name.
     *
     * @param dn the target entry's distinguished name, it must be a valid distinguished name.
     * @param attributeName the attribute's name
     * @param value a String value with which the target entry's attribute value to be compared with
     * @return <code>true</code> if the value matches, <code>false</code> otherwise
     * @throws LdapException if some error occurred
     */
    boolean compare( String dn, String attributeName, String value ) throws LdapException;


    /**
     * Compares whether a given attribute's value matches that of the
     * existing value of the attribute present in the entry with the given distinguished name.
     *
     * @param dn the target entry's distinguished name, it must be a valid distinguished name.
     * @param attributeName the attribute's name
     * @param value a byte[] value with which the target entry's attribute value to be compared with
     * @return <code>true</code> if the value matches, <code>false</code> otherwise
     * @throws LdapException if some error occurred
     */
    boolean compare( String dn, String attributeName, byte[] value ) throws LdapException;


    /**
     * Compares whether a given attribute's value matches that of the
     * existing value of the attribute present in the entry with the given distinguished name.
     *
     * @param dn the target entry's distinguished name, it must be a valid distinguished name.
     * @param attributeName the attribute's name
     * @param value a Value&lt;?&gt; value with which the target entry's attribute value to be compared with
     * @return <code>true</code> if the value matches, <code>false</code> otherwise
     * @throws LdapException if some error occurred
     */
    boolean compare( String dn, String attributeName, Value<?> value ) throws LdapException;


    /**
     * Compares whether a given attribute's value matches that of the
     * existing value of the attribute present in the entry with the given distinguished name.
     *
     * @param dn the target entry's distinguished name
     * @param attributeName the attribute's name
     * @param value a String value with which the target entry's attribute value to be compared with
     * @return <code>true</code> if the value matches, <code>false</code> otherwise
     * @throws LdapException if some error occurred
     */
    boolean compare( Dn dn, String attributeName, String value ) throws LdapException;


    /**
     * Compares whether a given attribute's value matches that of the
     * existing value of the attribute present in the entry with the given distinguished name.
     *
     * @param dn the target entry's distinguished name
     * @param attributeName the attribute's name
     * @param value a byte[] value with which the target entry's attribute value to be compared with
     * @return <code>true</code> if the value matches, <code>false</code> otherwise
     * @throws LdapException if some error occurred
     */
    boolean compare( Dn dn, String attributeName, byte[] value ) throws LdapException;


    /**
     * Compares whether a given attribute's value matches that of the
     * existing value of the attribute present in the entry with the given distinguished name.
     *
     * @param dn the target entry's distinguished name
     * @param attributeName the attribute's name
     * @param value a Value&lt;?&gt; value with which the target entry's attribute value to be compared with
     * @return <code>true</code> if the value matches, <code>false</code> otherwise
     * @throws LdapException if some error occurred
     */
    boolean compare( Dn dn, String attributeName, Value<?> value ) throws LdapException;


    /**
     * Compares an entry's attribute's value with that of the given value.
     *
     * @param compareRequest the compare request which contains the target distinguished name, 
     * attribute name and value
     * @return compare operation's response
     * @throws LdapException if some error occurred
     */
    CompareResponse compare( CompareRequest compareRequest ) throws LdapException;


    /**
     * Sends a extended operation request to the server with the given OID and no value.
     *
     * @param oid the object identifier of the extended operation
     * @return extended operation's response
     * @throws LdapException if some error occurred
     * @see #extended(org.apache.directory.api.asn1.util.Oid, byte[])
     */
    ExtendedResponse extended( String oid ) throws LdapException;


    /**
     * Sends a extended operation request to the server with the given OID and value.
     *
     * @param oid the object identifier of the extended operation
     * @param value value to be used by the extended operation, can be a null value
     * @return extended operation's response
     * @throws LdapException if some error occurred
     * @see #extended(org.apache.directory.api.asn1.util.Oid, byte[])
     */
    ExtendedResponse extended( String oid, byte[] value ) throws LdapException;


    /**
     * Sends a extended operation request to the server with the given OID and no value.
     *
     * @param oid the object identifier of the extended operation
     * @return extended operation's response
     * @throws LdapException if some error occurred
     * @see #extended(org.apache.directory.api.asn1.util.Oid, byte[])
     */
    ExtendedResponse extended( Oid oid ) throws LdapException;


    /**
     * Sends a extended operation request to the server with the given OID and value.
     *
     * @param oid the object identifier of the extended operation
     * @param value value to be used by the extended operation, can be a null value
     * @return extended operation's response
     * @throws LdapException if some error occurred
     */
    ExtendedResponse extended( Oid oid, byte[] value ) throws LdapException;


    /**
     * Performs an extended operation based on the extended request object.
     *
     * @param extendedRequest the extended operation's request
     * @return Extended operation's response
     * @throws LdapException if the extended operation failed
     */
    ExtendedResponse extended( ExtendedRequest extendedRequest ) throws LdapException;


    /**
     * Tells if an entry exists in the server.
     * 
     * @param dn The distinguished name of the entry to check for existence, must be a valid distinguished name.
     * @return <code>true</code> if the entry exists, <code>false</code> otherwise.
     * Note that if the entry exists but if the user does not have the permission to
     * read it, <code>false</code> will also be returned
     * @throws LdapException if some error occurred
     */
    boolean exists( String dn ) throws LdapException;


    /**
     * Tells if an Entry exists in the server.
     * 
     * @param dn The distinguished name of the entry to check for existence
     * @return <code>true</code> if the entry exists, <code>false</code> otherwise.
     * Note that if the entry exists but if the user does not have the permission to
     * read it, <code>false</code> will also be returned
     * @throws LdapException if some error occurred
     */
    boolean exists( Dn dn ) throws LdapException;


    /**
     * Get back the RooDSE from the connected server. Only the user attributes are returned.
     * 
     * @return The Entry containing all the information about the rootDSE
     * @throws LdapException If the rootDSE can't be read
     */
    Entry getRootDse() throws LdapException;


    /**
     * Get back the RooDSE from the connected server. The user can provide the
     * list of attributes he wants to get back. Sending "*" will return all the
     * user attributes, sending "+" will return all the operational attributes.
     * 
     * @param attributes The list of attributes to return
     * @return The Entry containing all the information about the rootDSE
     * @throws LdapException If the rootDSE can't be read
     */
    Entry getRootDse( String... attributes ) throws LdapException;


    /**
     * Searches for an entry having the given distinguished name.
     *
     * @param dn the distinguished name of the entry to be fetched
     * @return the Entry with the given distinguished name or null if no entry exists with that distinguished name.
     * @throws LdapException in case of any problems while searching for the distinguished name or if the returned 
     * response contains a referral
     * @see #lookup(Dn, String...)
     */
    Entry lookup( Dn dn ) throws LdapException;


    /**
     * Searches for an entry having the given distinguished name.
     *
     * @param dn the distinguished name of the entry to be fetched
     * @return the Entry with the given distinguished name or null if no entry exists with that distinguished name.
     * @throws LdapException in case of any problems while searching for the distinguished name or if the returned 
     * response contains a referral
     * @see #lookup(String, String...)
     */
    Entry lookup( String dn ) throws LdapException;


    /**
     * Searches for an entry having the given distinguished name.
     *
     * @param dn the distinguished name of the entry to be fetched
     * @param attributes the attributes to be returned along with entry
     * @return the Entry with the given distinguished name or null if no entry exists with 
     * that distinguished name.
     * @throws LdapException in case of any problems while searching for the distinguished name 
     * or if the returned response contains a referral
     */
    Entry lookup( Dn dn, String... attributes ) throws LdapException;


    /**
     * Searches for an entry having the given distinguished name.
     *
     * @param dn the distinguished name of the entry to be fetched
     * @param controls the controls to use
     * @param attributes the attributes to be returned along with entry
     * @return the Entry with the given distinguished name or null if no entry exists with
     *  that distinguished name.
     * @throws LdapException in case of any problems while searching for the distinguished name
     *  or if the returned response contains a referral
     */
    Entry lookup( Dn dn, Control[] controls, String... attributes ) throws LdapException;


    /**
     * Searches for an entry having the given distinguished name.
     *
     * @param dn the distinguished name of the entry to be fetched
     * @param attributes the attributes to be returned along with entry
     * @return the Entry with the given distinguished name or null if no entry exists with 
     * that distinguished name.
     * @throws LdapException in case of any problems while searching for the distinguished name
     *  or if the returned response contains a referral
     * @see #lookup(Dn, String...)
     */
    Entry lookup( String dn, String... attributes ) throws LdapException;


    /**
     * Searches for an entry having the given distinguished name.
     *
     * @param dn the distinguished name of the entry to be fetched
     * @param controls the controls to use
     * @param attributes the attributes to be returned along with entry
     * @return the Entry with the given distinguished name or null if no entry exists with 
     * that distinguished name.
     * @throws LdapException in case of any problems while searching for the distinguished name
     *  or if the returned response contains a referral
     * @see #lookup(Dn, String...)
     */
    Entry lookup( String dn, Control[] controls, String... attributes ) throws LdapException;


    /**
     * Checks if a control with the given OID is supported.
     *
     * @param controlOID the OID of the control
     * @return true if the control is supported, false otherwise
     * @throws LdapException if some error occurred
     */
    boolean isControlSupported( String controlOID ) throws LdapException;


    /**
     * Get the Controls supported by server.
     *
     * @return a list of control OIDs supported by server
     * @throws LdapException if some error occurred
     */
    List<String> getSupportedControls() throws LdapException;


    /**
     * Loads all the default schemas that are bundled with the API.<br><br>
     * <b>Note:</b> This method enables <b>all</b> schemas prior to loading.
     * 
     * @throws LdapException in case of problems while loading the schema
     */
    void loadSchema() throws LdapException;


    /**
     * Loads all the default schemas that are bundled with the API, in a relaxed mode.<br><br>
     * <b>Note:</b> This method enables <b>all</b> schemas prior to loading.<br>
     * The relaxed mode will allow inconsistencies in the schema.
     * 
     * @throws LdapException in case of problems while loading the schema
     */
    void loadSchemaRelaxed() throws LdapException;


    /**
     * @return The SchemaManager associated with this LdapConection if any
     */
    SchemaManager getSchemaManager();


    /**
     * Gets the LDAP CODEC service responsible for encoding and decoding
     * messages.
     * 
     * @return The LDAP CODEC service.
     */
    LdapApiService getCodecService();


    /**
     * Checks if a request has been completed, or not. 
     *
     * @param messageId ID of the request
     * @return true if the request has been completed, false is still being processed
     */
    boolean isRequestCompleted( int messageId );


    /**
     * Checks if there is a ResponseFuture associated with the given message ID.
     *
     * @param messageId ID of the request
     * @return true if there is a non-null future exists, false otherwise
     * @deprecated Use {@link #isRequestCompleted(int)}
     */
    @Deprecated
    boolean doesFutureExistFor( int messageId );


    /**
     * @return the object responsible for the detection of binary attributes
     */
    BinaryAttributeDetector getBinaryAttributeDetector();


    /**
     * Sets the object responsible for the detection of binary attributes.
     * 
     * @param binaryAttributeDetecter The Binary Attribute Detector to use
     */
    void setBinaryAttributeDetector( BinaryAttributeDetector binaryAttributeDetecter );


    /**
     * sets a SchemaManager to be used by this connection
     * @param schemaManager The SchemaManager to set
     */
    void setSchemaManager( SchemaManager schemaManager );
}