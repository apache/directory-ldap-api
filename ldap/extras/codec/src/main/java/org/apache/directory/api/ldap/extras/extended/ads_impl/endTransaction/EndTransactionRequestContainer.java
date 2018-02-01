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
package org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction;


import org.apache.directory.api.asn1.ber.AbstractContainer;


/**
 * A container for EndTransactionRequest codec.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class EndTransactionRequestContainer extends AbstractContainer
{
    /** EndTransactionRequest decorator*/
    private EndTransactionRequestDecorator endTransactionRequest;


    /**
     * Creates a new EndTransactionRequestContainer object. We will store one
     * grammar, it's enough ...
     */
    public EndTransactionRequestContainer()
    {
        super();
        setGrammar( EndTransactionRequestGrammar.getInstance() );
        setTransition( EndTransactionRequestStates.START_STATE );
    }


    /**
     * @return Returns the EndTransactionRequest instance.
     */
    public EndTransactionRequestDecorator getEndTransactionRequest()
    {
        return endTransactionRequest;
    }


    /**
     * Set a EndTransactionRequest Object into the container. It will be completed by
     * the ldapDecoder.
     * 
     * @param endTransactionRequestDecorator the EndTransactionRequest to set.
     */
    public void setEndTransactionRequest( EndTransactionRequestDecorator endTransactionRequestDecorator )
    {
        this.endTransactionRequest = endTransactionRequestDecorator;
    }


    /**
     * Clean the container for the next decoding.
     */
    @Override
    public void clean()
    {
        super.clean();
        endTransactionRequest = null;
    }
}
