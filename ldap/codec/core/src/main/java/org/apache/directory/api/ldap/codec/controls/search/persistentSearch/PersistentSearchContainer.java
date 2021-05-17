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
package org.apache.directory.api.ldap.codec.controls.search.persistentSearch;


import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.ldap.codec.api.ControlContainer;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.controls.PersistentSearch;


/**
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PersistentSearchContainer extends AbstractContainer implements ControlContainer
{
    /** PSearchControl */
    private Control control;

    /**
     * Creates a new PSearchControlContainer object pre-populated with a
     * PersistentSearch control
     *
     * @param control The PersistentSearch Control.
     */
    public PersistentSearchContainer( Control control )
    {
        super();
        setGrammar( PersistentSearchGrammar.getInstance() );
        setTransition( PersistentSearchStates.START_STATE );
        this.control = control;
    }


    /**
     * @return Returns the persistent search decorator.
     */
    public PersistentSearch getPersistentSearch()
    {

        return ( PersistentSearch ) control;
    }


    /**
     * Set a PSearchControl Object into the container. It will be completed by
     * the ldapDecoder.
     * 
     * @param control the PSearchControl to set.
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
