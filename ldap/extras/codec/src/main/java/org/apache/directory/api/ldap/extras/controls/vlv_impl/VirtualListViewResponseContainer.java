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

package org.apache.directory.api.ldap.extras.controls.vlv_impl;


import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewResponse;


/**
 * A container for the VLV response control.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class VirtualListViewResponseContainer extends AbstractContainer
{
    private VirtualListViewResponseDecorator control;

    private LdapApiService codec;


    /**
     * Creates a new VirtualListViewResponseContainer object.
     *
     * @param codec The LDAP Service to use
     */
    public VirtualListViewResponseContainer( LdapApiService codec )
    {
        super();
        this.codec = codec;
        setGrammar( VirtualListViewResponseGrammar.getInstance() );
        setTransition( VirtualListViewResponseStates.START_STATE );
    }


    /**
     * Creates a new VirtualListViewResponseContainer object.
     *
     * @param control The VLV control to decorate
     * @param codec The LDAP Service to use
     */
    public VirtualListViewResponseContainer( VirtualListViewResponseDecorator control, LdapApiService codec )
    {
        this( codec );
        decorate( control );
    }


    /**
     * @return The decorated VLV control
     */
    public VirtualListViewResponseDecorator getDecorator()
    {
        return control;
    }


    /**
     * Decorate a VLV control
     *  
     * @param control The VLV control to decorate
     */
    public void decorate( VirtualListViewResponse control )
    {
        if ( control instanceof VirtualListViewResponseDecorator )
        {
            this.control = ( VirtualListViewResponseDecorator ) control;
        }
        else
        {
            this.control = new VirtualListViewResponseDecorator( codec, control );
        }
    }


    /**
     * Set the VLV control
     * 
     * @param control The VLV control
     */
    public void setVirtualListViewResponseControl( VirtualListViewResponseDecorator control )
    {
        this.control = control;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void clean()
    {
        super.clean();
        control = null;
    }
}
