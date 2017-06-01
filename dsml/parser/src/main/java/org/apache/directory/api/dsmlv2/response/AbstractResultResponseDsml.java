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


import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.ResultResponse;


/**
 * Base class for all DSML responses.
 * 
 * @param <E> The response result type
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractResultResponseDsml<E extends ResultResponse>
    extends AbstractResponseDsml<E> implements ResultResponse
{
    /**
     * Instantiates a new abstract DSML response.
     *
     * @param codec The LDAP Service to use
     * @param resultResponse the LDAP message to decorate
     */
    public AbstractResultResponseDsml( LdapApiService codec, E resultResponse )
    {
        super( codec, resultResponse );
    }


    /**
     * {@inheritDoc}
     */
    public LdapResult getLdapResult()
    {
        return getDecorated().getLdapResult();
    }
}
