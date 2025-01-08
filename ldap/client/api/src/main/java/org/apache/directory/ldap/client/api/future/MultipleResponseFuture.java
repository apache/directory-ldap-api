/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
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


import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.ldap.client.api.LdapConnection;


/**
 * A Future implementation used in LdapConnection operations.
 *
 * @param <R> The result type returned by this Future's <code>get</code> method
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class MultipleResponseFuture<R extends Response> implements ResponseFuture<R>
{
    /** the blocking queue holding LDAP responses */
    protected BlockingQueue<R> queue;

    /** flag to determine if this future is cancelled */
    protected boolean cancelled = false;

    /** If the request has been cancelled because of an exception  it will be stored here */
    protected Throwable cause;

    /** The messageID for this future */
    protected int messageId;

    /** The connection used by the request */
    protected LdapConnection connection;


    /**
     * Creates a new instance of ResponseFuture.
     *
     * @param connection The LdapConnection used by the request
     * @param messageId The associated message ID
     */
    public MultipleResponseFuture( LdapConnection connection, int messageId )
    {
        queue = new LinkedBlockingQueue<>();
        this.messageId = messageId;
        this.connection = connection;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean cancel( boolean mayInterruptIfRunning )
    {
        if ( !cancelled )
        {
            // set the cancel flag first
            cancelled = true;
        
            // Send an abandonRequest only if this future exists
            if ( !connection.isRequestCompleted( messageId ) )
            {
                connection.abandon( messageId );
            }
        
            // then clear the queue, cause the might be some incoming messages before this abandon request
            // hits the server
            queue.clear();
        }

        return cancelled;
    }


    /**
     * {@inheritDoc}
     * @throws InterruptedException if the operation has been cancelled by client
     */
    @Override
    public R get() throws InterruptedException
    {
        return queue.take();
    }


    /**
     * Set the associated Response in this Future
     * 
     * @param response The response to add into the Future
     * @throws InterruptedException if the operation has been cancelled by client
     */
    @Override
    public void set( R response ) throws InterruptedException
    {
        queue.add( response );
    }


    /**
     * {@inheritDoc}
     * @throws InterruptedException if the operation has been cancelled by client
     */
    @Override
    public R get( long timeout, TimeUnit unit ) throws InterruptedException
    {
        return queue.poll( timeout, unit );
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
        throw new UnsupportedOperationException( I18n.err( I18n.ERR_04106_OPERATION_NOT_SUPPORTED ) );
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
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "[msgId : " ).append( messageId ).append( ", " );
        sb.append( "size : " ).append( queue.size() ).append( ", " );
        sb.append( "Canceled :" ).append( cancelled ).append( "]" );

        return sb.toString();
    }
}
