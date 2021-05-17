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
package org.apache.directory.api.ldap.codec.controls.search.pagedSearch;


import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.ldap.codec.api.ControlContainer;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;


/**
 * A container for the Paged Search Control.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class PagedResultsContainer extends AbstractContainer implements ControlContainer
{
    /** PagedSearchControl */
    private Control control;

    /**
     * Creates a new PagedSearchControl container object to contain a PagedResults
     * Control.
     *
     * @param control A PagedResults Control to store
     */
    public PagedResultsContainer( Control control )
    {
        super();
        setGrammar( PagedResultsGrammar.getInstance() );
        setTransition( PagedResultsStates.START_STATE );
        this.control = control;
    }


    /**
     * Set a PagedSearchControl Object into the container. It will be completed by
     * the ldapDecoder.
     * 
     * @param control the PagedSearchControl to set.
     */
    @Override
    public void setControl( Control control )
    {
        this.control = control;
    }


    /**
     * @return the control
     */
    public PagedResults getPagedResults()
    {
        return ( PagedResults ) control;
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
