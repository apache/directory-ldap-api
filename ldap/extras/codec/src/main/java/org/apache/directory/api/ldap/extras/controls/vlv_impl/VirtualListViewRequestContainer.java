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
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequest;


/**
 * A container for the VLV request control.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class VirtualListViewRequestContainer extends AbstractContainer
{
    private VirtualListViewRequestDecorator control;

    private LdapApiService codec;


    /**
     * Creates a new VirtualListViewRequestContainer instance
     * 
     * @param codec The LDAP Service to use
     */
    public VirtualListViewRequestContainer( LdapApiService codec )
    {
        super();
        this.codec = codec;
        setGrammar( VirtualListViewRequestGrammar.getInstance() );
        setTransition( VirtualListViewRequestStates.START_STATE );
    }


    /**
     * Creates a new VirtualListViewRequestContainer instance
     * 
     * @param control The VLV control
     * @param codec The LDAP Service to use
     */
    public VirtualListViewRequestContainer( VirtualListViewRequestDecorator control, LdapApiService codec )
    {
        this( codec );
        decorate( control );
    }


    /**
     * @return The VLV control
     */
    public VirtualListViewRequestDecorator getDecorator()
    {
        return control;
    }


    /**
     * Decorate he VLV control
     * 
     * @param control The control to decorate
     */
    public void decorate( VirtualListViewRequest control )
    {
        if ( control instanceof VirtualListViewRequestDecorator )
        {
            this.control = ( VirtualListViewRequestDecorator ) control;
        }
        else
        {
            this.control = new VirtualListViewRequestDecorator( codec, control );
        }
    }


    /**
     * Sets the VLV control
     * 
     * @param control The VLV control
     */
    public void setVirtualListViewRequestControl( VirtualListViewRequestDecorator control )
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
