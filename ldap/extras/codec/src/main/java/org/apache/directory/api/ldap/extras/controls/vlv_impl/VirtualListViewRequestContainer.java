/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
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
import org.apache.directory.api.ldap.codec.api.ControlContainer;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequest;
import org.apache.directory.api.ldap.model.message.Control;


/**
 * A container for the VLV request control.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class VirtualListViewRequestContainer extends AbstractContainer implements ControlContainer
{
    /** The VLV request control */
    private Control control;

    /**
     * Creates a new VirtualListViewRequestContainer instance
     * 
     * @param control The VLV control to store
     */
    public VirtualListViewRequestContainer( Control control )
    {
        super();
        setGrammar( VirtualListViewRequestGrammar.getInstance() );
        setTransition( VirtualListViewRequestStates.START_STATE );
        this.control = control;
    }


    /**
     * Get the VLV control
     * 
     * @return The VLV control
     */
    public VirtualListViewRequest getVirtualListViewRequest()
    {
        return ( VirtualListViewRequest ) control;
    }


    /**
     * Sets the VLV control
     * 
     * @param control The VLV control
     */
    public void setControl( Control control )
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
