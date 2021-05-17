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
package org.apache.directory.api.ldap.codec.controls.search.subentries;


import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.ldap.codec.api.ControlContainer;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.controls.Subentries;


/**
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SubentriesContainer extends AbstractContainer implements ControlContainer
{
    /** Subentries Control */
    private Control control;

    /**
     * Creates a new SubEntryControlContainer object, pre-populating it with the
     * supplied Subentries control.
     *
     * @param control The Subentries Control to add to this container
     */
    public SubentriesContainer( Control control )
    {
        super();
        setGrammar( SubentriesGrammar.getInstance() );
        setTransition( SubentriesStates.START_STATE );
        this.control = control;
    }


    /**
     * @return Returns the persistent search control.
     */
    public Subentries getSubentriesControl()
    {
        return ( Subentries ) control;
    }


    /**
     * Set a SubEntryControl Object into the container. It will be completed by
     * the ldapDecoder.
     * 
     * @param control the SubEntryControl to set.
     */
    public void setControl( Control control )
    {
        this.control = control;
    }


    /**
     * Clean the current container
     */
    @Override
    public void clean()
    {
        super.clean();
        control = null;
    }
}
