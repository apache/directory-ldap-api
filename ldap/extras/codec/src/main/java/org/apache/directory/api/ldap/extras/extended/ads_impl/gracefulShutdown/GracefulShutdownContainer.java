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
package org.apache.directory.api.ldap.extras.extended.ads_impl.gracefulShutdown;


import org.apache.directory.api.asn1.ber.AbstractContainer;


/**
 * A container for the GracefulShutdown codec.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class GracefulShutdownContainer extends AbstractContainer
{
    /** GracefulShutdown */
    private GracefulShutdownRequestDecorator gracefulShutdownRequest;


    /**
     * Creates a new GracefulShutdownContainer object. We will store one
     * grammar, it's enough ...
     */
    public GracefulShutdownContainer()
    {
        super();
        setGrammar( GracefulShutdownGrammar.getInstance() );
        setTransition( GracefulShutdownStatesEnum.START_STATE );
    }


    /**
     * @return Returns the Graceful Shutdown object.
     */
    public GracefulShutdownRequestDecorator getGracefulShutdownRequest()
    {
        return gracefulShutdownRequest;
    }


    /**
     * Set a GracefulShutdown Object into the container. It will be completed by
     * the ldapDecoder.
     * 
     * @param gracefulShutdown the GracefulShutdown to set.
     */
    public void setGracefulShutdownRequest( GracefulShutdownRequestDecorator gracefulShutdown )
    {
        this.gracefulShutdownRequest = gracefulShutdown;
    }


    /**
     * Clean the container for the next decoding.
     */
    @Override
    public void clean()
    {
        super.clean();
        gracefulShutdownRequest = null;
    }
}
