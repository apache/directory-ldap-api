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
package org.apache.directory.api.ldap.extras.extended.ads_impl.startTls;


import org.apache.directory.api.ldap.codec.api.AbstractExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.startTls.StartTlsRequest;
import org.apache.directory.api.ldap.extras.extended.startTls.StartTlsRequestImpl;
import org.apache.directory.api.ldap.extras.extended.startTls.StartTlsResponse;
import org.apache.directory.api.ldap.extras.extended.startTls.StartTlsResponseImpl;


/**
 * An {@link ExtendedOperationFactory} for creating SartTls extended reques/response 
 * pairs.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StartTlsFactory extends AbstractExtendedOperationFactory
{
    /**
     * Creates a new instance of StartTlsFactory.
     *
     * @param codec The codec for this factory.
     */
    public StartTlsFactory( LdapApiService codec )
    {
        super( codec, StartTlsRequest.EXTENSION_OID );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getOid()
    {
        return StartTlsRequest.EXTENSION_OID;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StartTlsRequest newRequest()
    {
        return new StartTlsRequestImpl();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public StartTlsResponse newResponse()
    {
        return new StartTlsResponseImpl();
    }
}
