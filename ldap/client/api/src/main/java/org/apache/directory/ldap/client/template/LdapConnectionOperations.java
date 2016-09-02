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
package org.apache.directory.ldap.client.template;


import java.util.List;

import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.AddResponse;
import org.apache.directory.api.ldap.model.message.DeleteRequest;
import org.apache.directory.api.ldap.model.message.DeleteResponse;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyResponse;
import org.apache.directory.api.ldap.model.message.ResultResponse;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.search.FilterBuilder;
import org.apache.directory.ldap.client.template.exception.PasswordException;


/**
 * Specifies the set of operations available on
 * {@link org.apache.directory.ldap.client.template.LdapConnectionTemplate
 * LdapConnectionTemplate}.  This interface can be useful for unit testing
 * in order to stub out methods.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface LdapConnectionOperations
{

    /**
     * Adds an entry specified by an AddRequest to the LDAP server.
     *
     * @param addRequest The request
     * @return An AddResponse
     */
    AddResponse add( AddRequest addRequest );


    /**
     * Adds an entry specified by a Dn and an array of Attribute's to the LDAP
     * server.
     *
     * @param dn The distinguished name of the new entry
     * @param attributes The attributes of the new entry
     * @return An AddResponse
     */
    AddResponse add( Dn dn, Attribute... attributes );


    /**
     * Adds an entry specified by a Dn, to be filled out by a RequestBuilder,
     * to the LDAP server.
     *
     * @param dn The distinguished name of the new entry
     * @param requestBuilder The request builder
     * @return An AddResponse
     */
    AddResponse add( Dn dn, RequestBuilder<AddRequest> requestBuilder );


    /**
     * Attempts to authenticate the supplied credentials against the first 
     * entry found matching the search criteria.  If authentication fails, 
     * a PasswordException is thrown.  If successful, the response is 
     * checked for warnings, and if present, a PasswordWarning is returned.
     * Otherwise, null is returned.
     *
     * @param baseDn The base DN from which to start the search for the user to authenticate
     * @param filter The filter selecting the entries
     * @param scope The scope to look from
     * @param password The password
     * @return A PasswordWarning or null
     * @throws PasswordException If the authentication failed
     * @see #authenticate(Dn, char[])
     * @see #searchFirst(String, String, SearchScope, EntryMapper)
     */
    PasswordWarning authenticate( String baseDn, String filter, SearchScope scope, char[] password )
        throws PasswordException;


    /**
     * Attempts to authenticate the supplied credentials against the first 
     * entry found matching the search criteria.  If authentication fails, 
     * a PasswordException is thrown.  If successful, the response is 
     * checked for warnings, and if present, a PasswordWarning is returned.
     * Otherwise, null is returned.
     *
     * @param baseDn The base DN from which to start the search for the user to authenticate
     * @param filter The filter selecting the entries
     * @param scope The scope to look from
     * @param password The password
     * @return A PasswordWarning or null
     * @throws PasswordException If the authentication failed
     * @see #authenticate(Dn, char[])
     * @see #searchFirst(Dn, String, SearchScope, EntryMapper)
     */
    PasswordWarning authenticate( Dn baseDn, String filter, SearchScope scope, char[] password )
        throws PasswordException;


    /**
     * Attempts to authenticate the supplied credentials against the first 
     * entry found matching the search criteria.  If authentication fails, 
     * a PasswordException is thrown.  If successful, the response is 
     * checked for warnings, and if present, a PasswordWarning is returned.
     * Otherwise, null is returned.
     *
     * @param searchRequest The SearchRequst to use to find the user to authenticate
     * @param password The password
     * @return A PasswordWarning or null
     * @throws PasswordException If the authentication failed
     * @see #authenticate(Dn, char[])
     * @see #searchFirst(SearchRequest, EntryMapper)
     */
    PasswordWarning authenticate( SearchRequest searchRequest, char[] password ) throws PasswordException;


    /**
     * Attempts to authenticate the supplied credentials.  If authentication
     * fails, a PasswordException is thrown.  If successful, the response is 
     * checked for warnings, and if present, a PasswordWarning is returned.
     * Otherwise, null is returned.
     *
     * @param userDn The distinguished name of the user
     * @param password The password
     * @return A PasswordWarning or null
     * @throws PasswordException If authentication fails
     */
    PasswordWarning authenticate( Dn userDn, char[] password ) throws PasswordException;


    /**
     * Deletes an entry specified by a DeleteRequest from the LDAP server.
     *
     * @param deleteRequest The request
     * @return A DeleteResponse
     */
    DeleteResponse delete( DeleteRequest deleteRequest );


    /**
     * Deletes an entry specified by Dn from the LDAP server.
     *
     * @param dn The distinguished name of the entry
     * @return A DeleteResponse
     */
    DeleteResponse delete( Dn dn );


    /**
     * Deletes an entry specified by Dn, and whose request is configured
     * by a RequestBuilder, from the LDAP server.
     *
     * @param dn The distinguished name of the entry
     * @param requestBuilder The RequestBuilder
     * @return A DeleteResponse
     */
    DeleteResponse delete( Dn dn, RequestBuilder<DeleteRequest> requestBuilder );


    /**
     * Executes the <code>connectionCallback</code>, supplying it a managed
     * connection.
     *
     * @param connectionCallback The callback
     * @param <T> The type of the mapped entry
     * @return Whatever the callback returns
     */
    <T> T execute( ConnectionCallback<T> connectionCallback );


    /**
     * Performs a lookup, and supplies the matching entry to the 
     * <code>entryMapper</code>.
     *
     * @param dn The distinguished name of the entry
     * @param entryMapper The mapper from entry to model object
     * @param <T> The type of the mapped entry
     * @return Whatever the <code>entryMapper</code> returns
     */
    <T> T lookup( Dn dn, EntryMapper<T> entryMapper );


    /**
     * Performs a lookup, requesting <code>attributes</code>, and supplies 
     * the matching entry to the <code>entryMapper</code>.
     *
     * @param dn The distinguished name of the entry
     * @param attributes The attributes to be fetched
     * @param entryMapper The mapper from entry to model object
     * @param <T> The type of the mapped entry
     * @return Whatever the <code>entryMapper</code> returns
     */
    <T> T lookup( Dn dn, String[] attributes, EntryMapper<T> entryMapper );


    /**
     * Modifies the password for <code>userDn</code> to
     * <code>newPassword</code> using the admin account.
     *
     * @param userDn The DN of the entry we want to modify the pwassword for
     * @param newPassword The new password
     * @throws PasswordException If the password change failed
     * @see #modifyPassword(Dn, char[], char[], boolean)
     */
    void modifyPassword( Dn userDn, char[] newPassword )
        throws PasswordException;


    /**
     * Modifies the password for <code>userDn</code> from 
     * <code>oldPassword</code> to <code>newPassword</code>.
     *
     * @param userDn The DN of the entry we want to modify the pwassword for
     * @param oldPassword The old password
     * @param newPassword The new password
     * @throws PasswordException If the password change failed
     * @see #modifyPassword(Dn, char[], char[], boolean)
     */
    void modifyPassword( Dn userDn, char[] oldPassword,
        char[] newPassword ) throws PasswordException;


    /**
     * Modifies the password for <code>userDn</code> from 
     * <code>oldPassword</code> to <code>newPassword</code>, optionally using
     * an admin account.  If <code>asAdmin</code> is true, then the operation
     * is performed in admin context which means <code>oldPassword</code> is
     * may be <code>null</code>.
     *
     * @param userDn The distinguished name of the user
     * @param oldPassword The users old password (optional if asAdmin is true)
     * @param newPassword The users new password
     * @param asAdmin If true, execute in admin context
     * @throws PasswordException If the password modification fails
     */
    void modifyPassword( Dn userDn, char[] oldPassword, char[] newPassword,
        boolean asAdmin ) throws PasswordException;


    /**
     * Modifies an entry specified by a ModifyRequest on the LDAP server.
     *
     * @param modifyRequest The request
     * @return A ModifyResponse
     */
    ModifyResponse modify( ModifyRequest modifyRequest );


    /**
     * Modifies an entry specified by Dn, and whose request is configured
     * by a RequestBuilder, on the LDAP server.
     *
     * @param dn The distinguished name of the entry
     * @param requestBuilder The RequestBuilder
     * @return A ModifyResponse
     */
    ModifyResponse modify( Dn dn, RequestBuilder<ModifyRequest> requestBuilder );


    /**
     * Checks the supplied response for its result code, and if not 
     * ResultCodeEnum#SUCCESS, an exception is thrown. This method is 
     * intended to be used inline:
     * 
     * <pre>
     * template.responseOrException( template.delete( dn ) );
     * </pre>
     *
     * @param response The response to check for success
     * @param <T> The type of response
     * @return The supplied <code>response</code>
     */
    <T extends ResultResponse> T responseOrException( T response );


    /**
     * Searches for the entries matching the supplied criteria, feeding the 
     * result into the <code>entryMapper</code>.
     *
     * @param baseDn The base DN from which to start the search
     * @param filter The filter selecting the entries
     * @param scope The scope to look from
     * @param entryMapper The mapper
     * @param <T> The type of the mapped entry
     * @return The mapped entries
     * @see #search(SearchRequest, EntryMapper)
     */
    <T> List<T> search( String baseDn, FilterBuilder filter, SearchScope scope,
        EntryMapper<T> entryMapper );


    /**
     * Searches for the entries matching the supplied criteria, feeding the 
     * result into the <code>entryMapper</code>.
     *
     * @param baseDn The base DN from which to start the search
     * @param filter The filter selecting the entries
     * @param scope The scope to look from
     * @param entryMapper The mapper
     * @param <T> The type of the mapped entry
     * @return The mapped entries
     * @see #search(SearchRequest, EntryMapper)
     */
    <T> List<T> search( String baseDn, String filter, SearchScope scope,
        EntryMapper<T> entryMapper );


    /**
     * Searches for the entries matching the supplied criteria, feeding the 
     * result into the <code>entryMapper</code>.
     *
     * @param baseDn The base DN from which to start the search
     * @param filter The filter selecting the entries
     * @param scope The scope to look from
     * @param entryMapper The mapper
     * @param <T> The type of the mapped entry
     * @return The mapped entries
     * @see #search(SearchRequest, EntryMapper)
     */
    <T> List<T> search( Dn baseDn, FilterBuilder filter, SearchScope scope,
        EntryMapper<T> entryMapper );


    /**
     * Searches for the entries matching the supplied criteria, feeding the 
     * result into the <code>entryMapper</code>.
     *
     * @param baseDn The base DN from which to start the search
     * @param filter The filter selecting the entries
     * @param scope The scope to look from
     * @param entryMapper The mapper
     * @param <T> The type of the mapped entry
     * @return The mapped entries
     * @see #search(SearchRequest, EntryMapper)
     */
    <T> List<T> search( Dn baseDn, String filter, SearchScope scope,
        EntryMapper<T> entryMapper );


    /**
     * Searches for the entries matching the supplied criteria, feeding the 
     * result into the <code>entryMapper</code>, querying only the requested 
     * attributes.
     *
     * @param baseDn The base DN from which to start the search
     * @param filter The filter selecting the entries
     * @param scope The scope to look from
     * @param attributes The list of AttributeType to return
     * @param entryMapper The mapper
     * @param <T> The type of the mapped entry
     * @return The mapped entries
     * @see #search(SearchRequest, EntryMapper)
     */
    <T> List<T> search( String baseDn, FilterBuilder filter, SearchScope scope,
        String[] attributes, EntryMapper<T> entryMapper );


    /**
     * Searches for the entries matching the supplied criteria, feeding the 
     * result into the <code>entryMapper</code>, querying only the requested 
     * attributes.
     *
     * @param baseDn The base DN from which to start the search
     * @param filter The filter selecting the entries
     * @param scope The scope to look from
     * @param attributes The list of AttributeType to return
     * @param entryMapper The mapper
     * @param <T> The type of the mapped entry
     * @return The mapped entries
     * @see #search(SearchRequest, EntryMapper)
     */
    <T> List<T> search( String baseDn, String filter, SearchScope scope,
        String[] attributes, EntryMapper<T> entryMapper );


    /**
     * Searches for the entries matching the supplied criteria, feeding the 
     * result into the <code>entryMapper</code>, querying only the requested 
     * attributes.
     *
     * @param baseDn The base DN from which to start the search
     * @param filter The filter selecting the entries
     * @param scope The scope to look from
     * @param attributes The list of AttributeType to return
     * @param entryMapper The mapper
     * @param <T> The type of the mapped entry
     * @return The mapped entries
     * @see #search(SearchRequest, EntryMapper)
     */
    <T> List<T> search( Dn baseDn, FilterBuilder filter, SearchScope scope,
        String[] attributes, EntryMapper<T> entryMapper );


    /**
     * Searches for the entries matching the supplied criteria, feeding the 
     * result into the <code>entryMapper</code>, querying only the requested 
     * attributes.
     *
     * @param baseDn The base DN from which to start the search
     * @param filter The filter selecting the entries
     * @param scope The scope to look from
     * @param attributes The list of AttributeType to return
     * @param entryMapper The mapper
     * @param <T> The type of the mapped entry
     * @return The mapped entries
     * @see #search(SearchRequest, EntryMapper)
     */
    <T> List<T> search( Dn baseDn, String filter, SearchScope scope,
        String[] attributes, EntryMapper<T> entryMapper );


    /**
     * Searches for the entries matching the supplied 
     * <code>searchRequest</code>, feeding the result into the 
     * <code>entryMapper</code>.
     *
     * @param searchRequest The search request
     * @param entryMapper The mapper
     * @param <T> The type of the mapped entry
     * @return The mapped entries
     */
    <T> List<T> search( SearchRequest searchRequest,
        EntryMapper<T> entryMapper );


    /**
     * Searches for the first entry matching the supplied criteria, feeding the 
     * result into the <code>entryMapper</code>.
     *
     * @param baseDn The base DN from which to start the search
     * @param filter The filter selecting the entries
     * @param scope The scope to look from
     * @param entryMapper The mapper
     * @param <T> The type of the mapped entry
     * @return The mapped entries
     * @see #searchFirst(SearchRequest, EntryMapper)
     */
    <T> T searchFirst( String baseDn, FilterBuilder filter, SearchScope scope,
        EntryMapper<T> entryMapper );


    /**
     * Searches for the first entry matching the supplied criteria, feeding the 
     * result into the <code>entryMapper</code>.
     *
     * @param baseDn The base DN from which to start the search
     * @param filter The filter selecting the entries
     * @param scope The scope to look from
     * @param entryMapper The mapper
     * @param <T> The type of the mapped entry
     * @return The mapped entries
     * @see #searchFirst(SearchRequest, EntryMapper)
     */
    <T> T searchFirst( String baseDn, String filter, SearchScope scope,
        EntryMapper<T> entryMapper );


    /**
     * Searches for the first entry matching the supplied criteria, feeding the 
     * result into the <code>entryMapper</code>.
     *
     * @param baseDn The base DN from which to start the search
     * @param filter The filter selecting the entries
     * @param scope The scope to look from
     * @param entryMapper The mapper
     * @param <T> The type of the mapped entry
     * @return The mapped entries
     * @see #searchFirst(SearchRequest, EntryMapper)
     */
    <T> T searchFirst( Dn baseDn, FilterBuilder filter, SearchScope scope,
        EntryMapper<T> entryMapper );


    /**
     * Searches for the first entry matching the supplied criteria, feeding the 
     * result into the <code>entryMapper</code>.
     *
     * @param baseDn The base DN from which to start the search
     * @param filter The filter selecting the entries
     * @param scope The scope to look from
     * @param entryMapper The mapper
     * @param <T> The type of the mapped entry
     * @return The mapped entries
     * @see #searchFirst(SearchRequest, EntryMapper)
     */
    <T> T searchFirst( Dn baseDn, String filter, SearchScope scope,
        EntryMapper<T> entryMapper );


    /**
     * Searches for the first entry matching the supplied criteria, feeding the 
     * result into the <code>entryMapper</code>, querying only the requested 
     * attributes.
     *
     * @param baseDn The base DN from which to start the search
     * @param filter The filter selecting the entries
     * @param scope The scope to look from
     * @param attributes The list of AttributeType to return
     * @param entryMapper The mapper
     * @param <T> The type of the mapped entry
     * @return The mapped entries
     * @see #searchFirst(SearchRequest, EntryMapper)
     */
    <T> T searchFirst( String baseDn, FilterBuilder filter, SearchScope scope,
        String[] attributes, EntryMapper<T> entryMapper );


    /**
     * Searches for the first entry matching the supplied criteria, feeding the 
     * result into the <code>entryMapper</code>, querying only the requested 
     * attributes.
     *
     * @param baseDn The base DN from which to start the search
     * @param filter The filter selecting the entries
     * @param scope The scope to look from
     * @param attributes The list of AttributeType to return
     * @param entryMapper The mapper
     * @param <T> The type of the mapped entry
     * @return The mapped entries
     * @see #searchFirst(SearchRequest, EntryMapper)
     */
    <T> T searchFirst( String baseDn, String filter, SearchScope scope,
        String[] attributes, EntryMapper<T> entryMapper );


    /**
     * Searches for the first entry matching the supplied criteria, feeding the 
     * result into the <code>entryMapper</code>, querying only the requested 
     * attributes.
     *
     * @param baseDn The base DN from which to start the search
     * @param filter The filter selecting the entries
     * @param scope The scope to look from
     * @param attributes The list of AttributeType to return
     * @param entryMapper The mapper
     * @param <T> The type of the mapped entry
     * @return The mapped entries
     * @see #searchFirst(SearchRequest, EntryMapper)
     */
    <T> T searchFirst( Dn baseDn, FilterBuilder filter, SearchScope scope,
        String[] attributes, EntryMapper<T> entryMapper );


    /**
     * Searches for the first entry matching the supplied criteria, feeding the 
     * result into the <code>entryMapper</code>, querying only the requested 
     * attributes.
     *
     * @param baseDn The base DN from which to start the search
     * @param filter The filter selecting the entries
     * @param scope The scope to look from
     * @param attributes The list of AttributeType to return
     * @param entryMapper The mapper
     * @param <T> The type of the mapped entry
     * @return The mapped entries
     * @see #searchFirst(SearchRequest, EntryMapper)
     */
    <T> T searchFirst( Dn baseDn, String filter, SearchScope scope,
        String[] attributes, EntryMapper<T> entryMapper );


    /**
     * Searches for the first entry matching the supplied 
     * <code>searchRequest</code>, feeding the result into the 
     * <code>entryMapper</code>. This is basically the same as 
     * {@link #search(SearchRequest, EntryMapper)}, but is optimized by
     * modifying the <code>searchRequest</code> to set its size limit to 1.
     * The <code>searchRequest</code> is returned to its original size limit
     * before this method returns (or throws an exception).
     *
     * @param searchRequest The search request
     * @param entryMapper The mapper
     * @param <T> The type of the mapped entry
     * @return The mapped entry
     */
    <T> T searchFirst( SearchRequest searchRequest,
        EntryMapper<T> entryMapper );

}