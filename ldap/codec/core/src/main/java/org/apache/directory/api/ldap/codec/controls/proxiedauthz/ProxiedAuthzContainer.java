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
package org.apache.directory.api.ldap.codec.controls.proxiedauthz;


import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.message.controls.ProxiedAuthz;


/**
 * The ProxiedAuthz control container.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ProxiedAuthzContainer extends AbstractContainer
{
    /** ProxiedAuthzControl */
    private ProxiedAuthzDecorator control;

    /** The codec that encodes and decodes */
    private LdapApiService codec;


    /**
     * Creates a new ProxiedAuthzContainer object. We will store one
     * grammar, it's enough ...
     */
    public ProxiedAuthzContainer( LdapApiService codec )
    {
        super();
        this.codec = codec;
        grammar = ProxiedAuthzGrammar.getInstance();
        setTransition( ProxiedAuthzStates.START_STATE );
    }


    /**
     * Creates a container with decorator, optionally decorating the supplied
     * Control if it is not a decorator implementation.
     *
     * @param control The EntryChange ControlDecorator, or a Control to be
     * wrapped by a new decorator.
     */
    public ProxiedAuthzContainer( LdapApiService codec, ProxiedAuthz control )
    {
        this( codec );
        decorate( control );
    }


    /**
     * @return Returns the ProxiedAuthzControl.
     */
    public ProxiedAuthzDecorator getProxiedAuthzDecorator()
    {
        return control;
    }


    /**
     * Checks to see if the supplied ProxiedAuthz implementation is a decorator
     * and if so just sets the ProxiedAuthzDecorator to it. Otherwise the supplied
     * control is decorated by creating a new ProxiedAuthzDecorator to wrap the
     * object.
     *
     * @param control The ProxiedAuthz Control to wrap, if it is not a decorator.
     */
    public void decorate( ProxiedAuthz control )
    {
        if ( control instanceof ProxiedAuthzDecorator )
        {
            this.control = ( ProxiedAuthzDecorator ) control;
        }
        else
        {
            this.control = new ProxiedAuthzDecorator( codec, control );
        }
    }


    /**
     * Set a ProxiedAuthzontrol Object into the container. It will be completed
     * by the ldapDecoder.
     * 
     * @param control the ProxiedAuthzControl to set.
     */
    public void setProxiedAuthzDecorator( ProxiedAuthzDecorator control )
    {
        this.control = control;
    }


    /**
     * Clean the container
     */
    public void clean()
    {
        super.clean();
        control = null;
    }
}
