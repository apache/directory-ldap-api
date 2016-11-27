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
package org.apache.directory.api.ldap.extras.extended.gracefulShutdown;


import org.apache.directory.api.ldap.model.message.AbstractExtendedRequest;


/**
 * An extended operation requesting the server to shutdown it's LDAP service
 * port while allowing established clients to complete or abandon operations
 * already in progress. More information about this extended request is
 * available here: <a href="http://docs.safehaus.org:8080/x/GR">LDAP Extensions
 * for Graceful Shutdown</a>.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class GracefulShutdownRequestImpl extends AbstractExtendedRequest implements GracefulShutdownRequest
{
    /** Offline time after disconnection */
    private int timeOffline;

    /** Delay before disconnection */
    private int delay;


    /**
     * Instantiates a new graceful shutdown request.
     *
     * @param messageId the message id
     */
    public GracefulShutdownRequestImpl( int messageId )
    {
        this( messageId, UNDETERMINED, NOW );
    }


    /**
     * Instantiates a new graceful shutdown request.
     */
    public GracefulShutdownRequestImpl()
    {
        setRequestName( EXTENSION_OID );
    }


    /**
     * Instantiates a new graceful shutdown request.
     *
     * @param messageId the message id
     * @param timeOffline the offline time after disconnection, in minutes
     * @param delay the delay before disconnection, in seconds
     */
    public GracefulShutdownRequestImpl( int messageId, int timeOffline, int delay )
    {
        super( messageId );
        setRequestName( EXTENSION_OID );
        this.timeOffline = timeOffline;
        this.delay = delay;
    }


    // -----------------------------------------------------------------------
    // Parameters of the Extended Request Payload
    // -----------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public int getDelay()
    {
        return delay;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setDelay( int delay )
    {
        this.delay = delay;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getTimeOffline()
    {
        return timeOffline;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setTimeOffline( int timeOffline )
    {
        this.timeOffline = timeOffline;
    }


    @Override
    public GracefulShutdownResponse getResultResponse()
    {
        if ( getResponse() == null )
        {
            setResponse( new GracefulShutdownResponseImpl() );
        }

        return ( GracefulShutdownResponse ) getResponse();
    }
}
