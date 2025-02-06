/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    https://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.directory.api.ldap.extras.extended.ads_impl.cancel;


import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.ldap.extras.extended.cancel.CancelRequest;


/**
 * A container for the Cancel codec.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class CancelRequestContainer extends AbstractContainer
{
    /** Cancel */
    private CancelRequest cancelRequest;

    /**
     * Creates a new CancelContainer object. We will store one
     * grammar, it's enough ...
     */
    public CancelRequestContainer()
    {
        super();
        setGrammar( CancelRequestGrammar.getInstance() );
        setTransition( CancelStatesEnum.START_STATE );
    }


    /**
     * Get the cancel request 
     * 
     * @return Returns the Cancel object.
     */
    public CancelRequest getCancelRequest()
    {
        return cancelRequest;
    }


    /**
     * Set a Cancel Object into the container. It will be completed
     * by the ldapDecoder.
     * 
     * @param cancelRequest the Cancel to set.
     */
    public void setCancelRequest( CancelRequest cancelRequest )
    {
        this.cancelRequest = cancelRequest;
    }


    /**
     * Clean the container for the next decoding.
     */
    @Override
    public void clean()
    {
        super.clean();
        cancelRequest = null;
    }
}
