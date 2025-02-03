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
package org.apache.directory.api.ldap.codec.controls.sort;


import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.ldap.codec.api.ControlContainer;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.controls.SortKey;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;


/**
 * Container for SortRequestControl.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SortRequestContainer extends AbstractContainer implements ControlContainer
{
    /** the sort request control decorator */
    private Control control;

    /** current key that is being decoded */
    private SortKey currentKey;

    /**
     * Creates a new instance of SortRequestContainer.
     *
     * @param control the sort request control
     */
    public SortRequestContainer( Control control )
    {
        super();
        setGrammar( SortRequestGrammar.getInstance() );
        setTransition( SortRequestStates.START_STATE );
        this.control = control;
    }


    /**
     * Get the SortRequest control
     * 
     * @return the control
     */
    public SortRequest getControl()
    {
        return ( SortRequest ) control;
    }


    /**
     * Set the control
     * 
     * @param control the control to set
     */
    public void setControl( Control control )
    {
        this.control = control;
    }


    /**
     * Clean the container
     */
    @Override
    public void clean()
    {
        super.clean();
        control = null;
    }


    /**
     * Get the current key
     * 
     * @return the currentKey
     */
    public SortKey getCurrentKey()
    {
        return currentKey;
    }


    /**
     * Set the current key
     * 
     * @param currentKey the currentKey to set
     */
    public void setCurrentKey( SortKey currentKey )
    {
        this.currentKey = currentKey;
    }
}
