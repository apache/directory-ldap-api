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


import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.DeleteRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.search.FilterBuilder;


/**
 * A factory for creating {@link org.apache.directory.api.ldap.model} objects.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface ModelFactory
{
    /**
     * Returns a new <code>AddRequest</code> for the <code>entry</code>.
     *
     * @param entry
     * @return
     */
    public AddRequest newAddRequest( Entry entry );


    /**
     * Returns a new Attribute for with the provided <code>name</code> and
     * <code>value(s)</code>.
     *
     * @param name
     * @param values
     * @return
     */
    public Attribute newAttribute( String name, byte[]... values );
    
    
    /**
     * Returns a new Attribute for with the provided <code>name</code> and
     * <code>value(s)</code>.
     *
     * @param name
     * @param values
     * @return
     */
    public Attribute newAttribute( String name, String... values );
    
    
    /**
     * Returns a new Attribute for with the provided <code>name</code> and
     * <code>value(s)</code>.
     *
     * @param name
     * @param values
     * @return
     */
    public Attribute newAttribute( String name, Value<?>... values );


    /**
     * Returns a new <code>DeleteRequest</code> for the <code>dn</code>.
     *
     * @param dn
     * @return
     */
    public DeleteRequest newDeleteRequest( Dn dn );


    /**
     * Returns a <code>Dn</code> that represents <code>dn</code>.
     *
     * @param dn
     * @return
     */
    public Dn newDn( String dn );


    /**
     * Returns a <code>Entry</code> with the specified <code>dn</code>.
     *
     * @param dn
     * @return
     */
    public Entry newEntry( String dn );


    /**
     * Returns a <code>Entry</code> with the specified <code>dn</code>.
     *
     * @param dn
     * @return
     */
    public Entry newEntry( Dn dn );


    /**
     * Returns a new <code>ModifyRequest</code> for the <code>dn</code>.
     *
     * @param dn 
     * @return
     */
    public ModifyRequest newModifyRequest( String dn );


    /**
     * Returns a new <code>ModifyRequest</code> for the <code>dn</code>.
     *
     * @param dn
     * @return
     */
    public ModifyRequest newModifyRequest( Dn dn );


    /**
     * Returns a new <code>SearchRequest</code> over <code>baseDn</code> in
     * <code>scope</code> matching <code>filter</code> returning 
     * all normal attributes for each matching entry.
     *
     * @param baseDn
     * @param filter
     * @param scope
     * @return
     */
    public SearchRequest newSearchRequest( String baseDn, FilterBuilder filter,
        SearchScope scope );


    /**
     * Returns a new <code>SearchRequest</code> over <code>baseDn</code> in
     * <code>scope</code> matching <code>filter</code> returning 
     * all normal attributes for each matching entry.
     *
     * @param baseDn
     * @param filter
     * @param scope
     * @return
     */
    public SearchRequest newSearchRequest( String baseDn, String filter,
        SearchScope scope );


    /**
     * Returns a new <code>SearchRequest</code> over <code>baseDn</code> in
     * <code>scope</code> matching <code>filter</code> returning 
     * all normal attributes for each matching entry.
     *
     * @param baseDn
     * @param filter
     * @param scope
     * @return
     */
    public SearchRequest newSearchRequest( Dn baseDn, String filter,
        SearchScope scope );


    /**
     * Returns a new <code>SearchRequest</code> over <code>baseDn</code> in
     * <code>scope</code> matching <code>filter</code> returning 
     * all normal attributes for each matching entry.
     *
     * @param baseDn
     * @param filter
     * @param scope
     * @return
     */
    public SearchRequest newSearchRequest( Dn baseDn, FilterBuilder filter,
        SearchScope scope );


    /**
     * Returns a new <code>SearchRequest</code> over <code>baseDn</code> in
     * <code>scope</code> matching <code>filter</code> returning 
     * <code>attributes</code> for each matching entry.
     *
     * @param baseDn
     * @param filter
     * @param scope
     * @param attributes
     * @return
     */
    public SearchRequest newSearchRequest( String baseDn, String filter,
        SearchScope scope, String... attributes );


    /**
     * Returns a new <code>SearchRequest</code> over <code>baseDn</code> in
     * <code>scope</code> matching <code>filter</code> returning 
     * <code>attributes</code> for each matching entry.
     *
     * @param baseDn
     * @param filter
     * @param scope
     * @param attributes
     * @return
     */
    public SearchRequest newSearchRequest( String baseDn, FilterBuilder filter,
        SearchScope scope, String... attributes );


    /**
     * Returns a new <code>SearchRequest</code> over <code>baseDn</code> in
     * <code>scope</code> matching <code>filter</code> returning 
     * <code>attributes</code> for each matching entry.
     *
     * @param baseDn
     * @param filter
     * @param scope
     * @param attributes
     * @return
     */
    public SearchRequest newSearchRequest( Dn baseDn, String filter,
        SearchScope scope, String... attributes );


    /**
     * Returns a new <code>SearchRequest</code> over <code>baseDn</code> in
     * <code>scope</code> matching <code>filter</code> returning 
     * <code>attributes</code> for each matching entry.
     *
     * @param baseDn
     * @param filter
     * @param scope
     * @param attributes
     * @return
     */
    public SearchRequest newSearchRequest( Dn baseDn, FilterBuilder filter,
        SearchScope scope, String... attributes );
}
