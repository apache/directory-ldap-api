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
package org.apache.directory.api.dsmlv2.response;


import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.dsmlv2.DsmlDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.SearchResultDone;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchResultReference;
import org.dom4j.Element;
import org.dom4j.tree.DefaultElement;


/**
 * This class represents the Search Response Dsml Container. 
 * It is used to store Search Responses (Search Result Entry, 
 * Search Result Reference and SearchResultDone).
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SearchResponseDsml extends AbstractResponseDsml<Response>
{
    private static final String SEARCH_RESPONSE_TAG = "searchResponse";

    /** The responses */
    private List<DsmlDecorator<? extends Response>> responses =
        new ArrayList<DsmlDecorator<? extends Response>>();


    /**
     * Creates a new getDecoratedMessage() of SearchResponseDsml.
     * 
     * @param codec The LDAP Service to use
     */
    public SearchResponseDsml( LdapApiService codec )
    {
        super( codec, new SearchResponse() );
    }


    /**
     * Creates a new getDecoratedMessage() of SearchResponseDsml.
     *
     * @param codec The LDAP Service to use
     * @param response the LDAP response message to decorate
     */
    public SearchResponseDsml( LdapApiService codec, Message response )
    {
        super( codec, ( Response ) response );
    }


    /**
     * Adds a response.
     *
     * @param response
     *      the response to add
     * @return
     *      true (as per the general contract of the Collection.add method).
     */
    public boolean addResponse( DsmlDecorator<? extends Response> response )
    {
        if ( response instanceof SearchResultEntry )
        {
            ( ( SearchResponse ) getDecorated() ).addSearchResultEntry(
                ( SearchResultEntryDsml ) response );
        }
        else if ( response instanceof SearchResultReference )
        {
            ( ( SearchResponse ) getDecorated() ).addSearchResultReference(
                ( SearchResultReferenceDsml ) response );
        }
        else if ( response instanceof SearchResultDone )
        {
            ( ( SearchResponse ) getDecorated() ).setSearchResultDone(
                ( SearchResultDoneDsml ) response );
        }
        else
        {
            throw new IllegalArgumentException( "Unidentified search resp type" );
        }

        return responses.add( response );
    }


    /**
     * Removes a response.
     *
     * @param response
     *      the response to remove
     * @return
     *      true if this list contained the specified element.
     */
    public boolean removeResponse( DsmlDecorator<? extends Response> response )
    {
        if ( response instanceof SearchResultEntry )
        {
            ( ( SearchResponse ) getDecorated() ).removeSearchResultEntry(
                ( SearchResultEntryDsml ) response );
        }
        else if ( response instanceof SearchResultReference )
        {
            ( ( SearchResponse ) getDecorated() ).removeSearchResultReference(
                ( SearchResultReferenceDsml ) response );
        }
        else if ( response instanceof SearchResultDone )
        {
            if ( response.equals( ( ( SearchResponse ) getDecorated() ).getSearchResultDone() ) )
            {
                ( ( SearchResponse ) getDecorated() ).setSearchResultDone( null );
            }
        }
        else
        {
            throw new IllegalArgumentException( "Unidentified search resp type" );
        }

        return responses.remove( response );
    }


    /**
     * {@inheritDoc}
     */
    public Element toDsml( Element root )
    {
        Element element = null;

        if ( root != null )
        {
            element = root.addElement( SEARCH_RESPONSE_TAG );
        }
        else
        {
            element = new DefaultElement( SEARCH_RESPONSE_TAG );
        }

        // RequestID
        if ( getDecorated() != null )
        {
            int requestID = getDecorated().getMessageId();
            if ( requestID > 0 )
            {
                element.addAttribute( "requestID", Integer.toString( requestID ) );
            }
        }

        for ( DsmlDecorator<? extends Response> response : responses )
        {
            response.toDsml( element );
        }

        return element;
    }
}
