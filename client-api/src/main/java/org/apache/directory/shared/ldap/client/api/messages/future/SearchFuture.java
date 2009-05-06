/*
 * Licensed to the Apache Software Foundation (ASF) under one
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
package org.apache.directory.shared.ldap.client.api.messages.future;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.directory.shared.ldap.client.api.messages.Response;
import org.apache.directory.shared.ldap.client.api.messages.SearchResultDone;

/**
 * A Future to manage SearchRequest. The searchResponseQueue contains
 * all the entries or referral, with a last element being a searchResultDone 
 * response.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class SearchFuture implements Future<Response>
{
    /** The queue where SearchResponse are stored */
    private BlockingQueue<Response> searchResponseQueue;
    
    /** A flag set to true when the searchResultDone has been received */
    private boolean done = false;
   
    /**
     * 
     * Creates a new instance of SearchFuture.
     *
     * @param searchResponseQueue The associated SearchResponse queue
     */
    public SearchFuture( BlockingQueue<Response> searchResponseQueue )
    {
        this.searchResponseQueue = searchResponseQueue;
    }
    
    
    /**
     * {@inheritDoc}
     */
    public boolean cancel( boolean mayInterruptIfRunning )
    {
        throw new RuntimeException( "Not Yet Implemented" );
    }

    
    /**
     * Get the SearchResponse, blocking until one is received.
     * It can be either a SearchResultEntry, a SearchResultReference
     * or a SearchResultDone, the last of all the SearchResponse.
     * 
     * @return The Response (either a SearchResponse instance - ie entry 
     * or referral) or a SearchResultDone
     */
    public Response get() throws InterruptedException, ExecutionException
    {
        Response response = searchResponseQueue.take();
        
        if ( response instanceof SearchResultDone )
        {
            done = true;
        }
        
        return response;
    }

    
    /**
     * Get the SearchResponse, blocking until one is received, or until the
     * given timeout is reached.
     * 
     * @param timeout Number of TimeUnit to wait
     * @param unit The TimeUnit
     * @return The SearchResponse The SearchResponse found (either a 
     * SearchResponse instance - ie entry or referral) or a SearchResultDone
     */
    public Response get( long timeout, TimeUnit unit ) throws InterruptedException, ExecutionException,
        TimeoutException
    {
        return searchResponseQueue.poll( timeout, unit );        
    }

    
    /**
     * {@inheritDoc}
     */
    public boolean isCancelled()
    {
        throw new RuntimeException( "Not Yet Implemented" );
    }


    /**
     * {@inheritDoc}
     */
    public boolean isDone()
    {
        return done;
    }
}
