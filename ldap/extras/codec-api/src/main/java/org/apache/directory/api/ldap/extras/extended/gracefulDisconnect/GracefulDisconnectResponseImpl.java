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
package org.apache.directory.api.ldap.extras.extended.gracefulDisconnect;


import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.message.ExtendedResponseImpl;
import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.ldap.model.message.ReferralImpl;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;


/**
 * An unsolicited notification, extended response, intended for notifying
 * clients of up coming disconnection due to intended service windows. Unlike the
 * {@link org.apache.directory.api.ldap.model.message.extended.NoticeOfDisconnect} this response contains additional information about
 * the amount of time the server will be offline and exactly when it intends to
 * shutdown.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class GracefulDisconnectResponseImpl extends ExtendedResponseImpl implements GracefulDisconnectResponse
{
    /** Offline time after disconnection */
    private int timeOffline;

    /** Delay before disconnection */
    private int delay;

    /** String based LDAP URL that may be followed for replicated namingContexts */
    private Referral replicatedContexts = new ReferralImpl();


    /**
     * Instantiates a new graceful disconnect.
     */
    public GracefulDisconnectResponseImpl()
    {
        super( 0, EXTENSION_OID );
    }


    /**
     * Instantiates a new graceful disconnect.
     *
     * @param timeOffline the offline time after disconnect, in minutes
     * @param delay the delay before disconnect, in seconds
     */
    public GracefulDisconnectResponseImpl( int timeOffline, int delay )
    {
        super( 0, EXTENSION_OID );
        responseName = EXTENSION_OID;
        this.timeOffline = timeOffline;
        this.delay = delay;

        StringBuilder buf = new StringBuilder();
        buf.append( "The server will disconnect and will be unavailable for " ).append( timeOffline );
        buf.append( " minutes in " ).append( delay ).append( " seconds." );

        ldapResult.setDiagnosticMessage( buf.toString() );
        ldapResult.setMatchedDn( null );
        ldapResult.setResultCode( ResultCodeEnum.UNAVAILABLE );
    }


    /**
     * Gets the OID uniquely identifying this extended response (a.k.a. its
     * name).
     * 
     * @return the OID of the extended response type.
     */
    @Override
    public String getResponseName()
    {
        return EXTENSION_OID;
    }


    /**
     * Sets the OID uniquely identifying this extended response (a.k.a. its
     * name).
     * 
     * @param oid the OID of the extended response type.
     */
    @Override
    public void setResponseName( String oid )
    {
        throw new UnsupportedOperationException( I18n.err( I18n.ERR_04168, EXTENSION_OID ) );
    }


    // -----------------------------------------------------------------------
    // Parameters of the Extended Response Value
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
    public Referral getReplicatedContexts()
    {
        return replicatedContexts;
    }
    


    /**
     * {@inheritDoc}
     */
    @Override
    public void addReplicatedContexts( String replicatedContext )
    {
        replicatedContexts.addLdapUrl( replicatedContext );
    }
}
