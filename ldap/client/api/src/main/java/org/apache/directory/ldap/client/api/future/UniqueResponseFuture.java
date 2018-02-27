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
package org.apache.directory.ldap.client.api.future;

import java.util.concurrent.TimeUnit;

import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.ldap.client.api.LdapConnection;

/**
 * A Future implementation used in LdapConnection operations for operations
 * that only get one single response.
 *
 * @param <R> The result type returned by this Future's <tt>get</tt> method
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class UniqueResponseFuture<R extends Response> implements ResponseFuture<R>
{
    /** The response */
    private R response;

    /** flag to determine if this future is cancelled */
    protected boolean cancelled = false;

    /** If the request has been cancelled because of an exception  it will be stored here */
    protected Throwable cause;

    /** The messageID for this future */
    protected int messageId;

    /** The connection used by the request */
    protected LdapConnection connection;
    
    /** A flag set to TRUE when the response has been received */
    private volatile boolean done = false;

    /**
     * Creates a new instance of UniqueResponseFuture.
     *
     * @param connection The LdapConnection used by the request
     * @param messageId The associated message ID
     */
    public UniqueResponseFuture( LdapConnection connection, int messageId )
    {
        this.messageId = messageId;
        this.connection = connection;
    }


    /**
     * {@inheritDoc}
     * @throws InterruptedException if the operation has been cancelled by client
     */
    @Override
    public synchronized R get() throws InterruptedException
    {
        while ( !done && !cancelled )
        {
            wait();
        }
        
        return response;
    }


    /**
     * {@inheritDoc}
     * @throws InterruptedException if the operation has been cancelled by client
     */
    @Override
    public synchronized R get( long timeout, TimeUnit unit ) throws InterruptedException
    {
        wait( unit.toMillis( timeout ) );
        
        return response;
    }


    /**
     * Set the associated Response in this Future
     * 
     * @param response The response to add into the Future
     * @throws InterruptedException if the operation has been cancelled by client
     */
    public synchronized void set( R response ) throws InterruptedException
    {
        this.response = response;
        
        done = response != null;
        
        notifyAll();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean cancel( boolean mayInterruptIfRunning )
    {
        if ( cancelled )
        {
            return cancelled;
        }

        // set the cancel flag first
        cancelled = true;

        // Send an abandonRequest only if this future exists
        if ( !connection.isRequestCompleted( messageId ) )
        {
            connection.abandon( messageId );
        }
        
        // Notify the future
        try
        { 
            set( null );
        }
        catch ( InterruptedException ie )
        {
            // Nothing we can do
        }

        return cancelled;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isCancelled()
    {
        return cancelled;
    }


    /**
     * This operation is not supported in this implementation of Future.
     * 
     * {@inheritDoc}
     */
    @Override
    public boolean isDone()
    {
        return done;
    }


    /**
     * @return the cause
     */
    public Throwable getCause()
    {
        return cause;
    }


    /**
     * Associate a cause to the ResponseFuture
     * @param cause the cause to set
     */
    public void setCause( Throwable cause )
    {
        this.cause = cause;
    }


    /**
     * Cancel the Future
     *
     */
    public void cancel()
    {
        // set the cancel flag first
        cancelled = true;
        
        // Notify the future
        try
        { 
            set( null );
        }
        catch ( InterruptedException ie )
        {
            // Nothing we can do
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "[msgId : " ).append( messageId ).append( ", " );
        sb.append( "Canceled :" ).append( cancelled ).append( "]" );

        return sb.toString();
    }
}
