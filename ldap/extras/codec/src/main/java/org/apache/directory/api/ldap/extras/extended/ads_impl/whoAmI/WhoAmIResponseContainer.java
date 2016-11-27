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
package org.apache.directory.api.ldap.extras.extended.ads_impl.whoAmI;


import org.apache.directory.api.asn1.ber.AbstractContainer;


/**
 * A container for WhoAmIResponse codec.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class WhoAmIResponseContainer extends AbstractContainer
{
    /** WhoAmIResponse decorator*/
    private WhoAmIResponseDecorator whoAmIResponse;


    /**
     * Creates a new WhoAmIResponseContainer object. We will store one
     * grammar, it's enough ...
     */
    public WhoAmIResponseContainer()
    {
        super();
        setGrammar( WhoAmIResponseGrammar.getInstance() );
        setTransition( WhoAmIResponseStatesEnum.START_STATE );
    }


    /**
     * @return Returns the WhoAmIResponse instance.
     */
    public WhoAmIResponseDecorator getWhoAmIResponse()
    {
        return whoAmIResponse;
    }


    /**
     * Set a WhoAmIResponse Object into the container. It will be completed by
     * the ldapDecoder.
     * 
     * @param whoAmIResponseDecorator the WhoAmIResponse to set.
     */
    public void setWhoAmIResponse( WhoAmIResponseDecorator whoAmIResponseDecorator )
    {
        this.whoAmIResponse = whoAmIResponseDecorator;
    }


    /**
     * Clean the container for the next decoding.
     */
    @Override
    public void clean()
    {
        super.clean();
        whoAmIResponse = null;
    }
}
