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

package org.apache.directory.api.ldap.model.cursor;


import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.IntermediateResponse;
import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.SearchResultDone;


/**
 * An extension of Cursor which includes the retrieval of the SearchResultDone. 
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface SearchCursor extends Cursor<Response>
{
    /**
     * @return true if the cursor has processed all the elements we were searching
     */
    boolean isDone();


    /**
     * gives the SearchResultDone message received at the end of search results
     * 
     * @return the SearchResultDone message, null if the search operation fails for any reason 
     */
    SearchResultDone getSearchResultDone();


    /**
     * @return true if the next element in the cursor is a referral 
     */
    boolean isReferral();


    /**
     * @return The next referral element, if it's a referral 
     * @throws LdapException If the 
     */
    Referral getReferral() throws LdapException;


    /**
     * @return true if the next element in the cursor is an entry 
     */
    boolean isEntry();


    /**
     * @return The next entry element, if it's an entry 
     * @throws LdapException If the 
     */
    Entry getEntry() throws LdapException;


    /**
     * @return true if the next element in the cursor is an intermediate response 
     */
    boolean isIntermediate();


    /**
     * @return The next intermediate response element, if it's an intermediate response 
     * @throws LdapException If the 
     */
    IntermediateResponse getIntermediate() throws LdapException;
}
