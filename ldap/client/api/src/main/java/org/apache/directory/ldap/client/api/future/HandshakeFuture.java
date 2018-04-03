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
package org.apache.directory.ldap.client.api.future;


import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;


/**
 * A Future to manage StartTLS handshake
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class HandshakeFuture implements Future<Boolean>
{
    /** A flag set to TRUE when the handshake has been completed */
    private volatile boolean done = false;

    /** flag to determine if this future is cancelled */
    protected boolean cancelled = false;

    /**
     * Creates a new instance of HandshakeFuture.
     *
     * @param connection the LDAP connection
     * @param messageId The associated messageId
     */
    public HandshakeFuture()
    {
        // Nothing to initialize...
    }


    /**
     * Cancel the Future
     *
     */
    public synchronized void cancel()
    {
        // set the cancel flag first
        cancelled = true;
        
        // Notify the future
        notifyAll();
    }


    /**
     * Set the Future to done when the TLS handshake has completed
     * 
     * @throws InterruptedException if the operation has been cancelled by client
     */
    public synchronized void secured()
    {
        done = true;
        
        notifyAll();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized boolean cancel( boolean mayInterruptIfRunning )
    {
        if ( cancelled )
        {
            return cancelled;
        }

        // set the cancel flag first
        cancelled = true;

        // Notify the future
        notifyAll();

        return cancelled;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized Boolean get() throws InterruptedException, ExecutionException
    {
        while ( !done && !cancelled )
        {
            wait();
        }
        
        return done;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public synchronized Boolean get( long timeout, TimeUnit unit ) throws InterruptedException, ExecutionException, TimeoutException
    {
        wait( unit.toMillis( timeout ) );
        
        return done;
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
     * {@inheritDoc}
     */
    @Override
    public boolean isDone()
    {
        return done;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
    
        sb.append( "HandshakeFuture, completed: " ).append( done ).append( ", cancelled: " ).append( cancelled );
    
        return sb.toString();
    }
}
