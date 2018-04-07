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
package org.apache.directory.api.ldap.extras.intermediate.syncrepl_impl;

import org.apache.directory.api.ldap.codec.api.IntermediateResponseFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.intermediate.syncrepl.SyncInfoValue;
import org.apache.directory.api.ldap.extras.intermediate.syncrepl.SyncInfoValueImpl;
import org.apache.directory.api.ldap.model.message.IntermediateResponse;

/**
 * A factory to create a SyncInfoValue intermediate response
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SyncInfoFactory implements IntermediateResponseFactory
{
    /** The Codec service */
    private LdapApiService codec;

    /**
     * 
     */
    public SyncInfoFactory( LdapApiService codec )
    {
        this.codec = codec;
    }
    
    
    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return SyncInfoValue.OID;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public IntermediateResponse newResponse(  byte[] encodedValue  )
    {
        SyncInfoValueDecorator response = new SyncInfoValueDecorator( codec, new SyncInfoValueImpl() );
        response.setResponseValue( encodedValue );

        return response;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public SyncInfoValueDecorator decorate( IntermediateResponse decoratedMessage )
    {
        if ( decoratedMessage instanceof SyncInfoValueDecorator )
        {
            return ( SyncInfoValueDecorator ) decoratedMessage;
        }

        return new SyncInfoValueDecorator( codec, ( SyncInfoValue ) null );
    }
}
