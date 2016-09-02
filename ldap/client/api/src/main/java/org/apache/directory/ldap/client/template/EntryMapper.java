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


import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;


/**
 * A callback for processing entries from a search result.
 * 
 * @param <T> The type of the mapped entry
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface EntryMapper<T>
{
    /**
     * Will be called once for each entry in the search result.
     *
     * @param entry An entry from the search result
     * @return A object modeling the entry
     * @throws LdapException If something goes wrong
     */
    T map( Entry entry ) throws LdapException;
}