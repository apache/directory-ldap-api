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
import org.apache.directory.api.ldap.model.message.controls.SortResponse;


/**
 * Container for SortResponseControl.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SortResponseContainer extends AbstractContainer implements ControlContainer
{
    /** the decorator instance of sort response control */
    private Control control;

    /**
     * Creates a new instance of SortResponseContainer.
     *
     * @param control the sort response control
     */
    public SortResponseContainer( Control control )
    {
        super();
        setGrammar( SortResponseGrammar.getInstance() );
        setTransition( SortResponseStates.START_STATE );
        this.control = control;
    }


    /**
     * Get the SoreResponse control
     *  
     * @return the control
     */
    public SortResponse getControl()
    {
        return ( SortResponse ) control;
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
}
