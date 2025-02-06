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

package org.apache.directory.api.ldap.extras.extended.ads_impl.storedProcedure;


import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.ldap.extras.extended.storedProcedure.StoredProcedureParameter;
import org.apache.directory.api.ldap.extras.extended.storedProcedure.StoredProcedureRequest;


/**
 * A container for the StoredProcedure codec
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StoredProcedureRequestContainer extends AbstractContainer
{
    /** StoredProcedure */
    private StoredProcedureRequest storedProcedureRequest;
    
    /** The current parameter being decoded */
    private StoredProcedureParameter currentParameter;


    /**
     * Creates a new StoredProcedureContainer instance
     */
    public StoredProcedureRequestContainer()
    {
        super();
        setGrammar( StoredProcedureRequestGrammar.getInstance() );
        setTransition( StoredProcedureStatesEnum.START_STATE );
    }


    /**
     * Get the StoredProcedureRequest
     * 
     * @return Returns the StoredProcedureRequest.
     */
    public StoredProcedureRequest getStoredProcedure()
    {
        return storedProcedureRequest;
    }


    /**
     * Set a StoredProcedure object into the container. It will be completed by the
     * ldapDecoder.
     * 
     * @param storedProcedureRequest The Stored Procedure to set
     */
    public void setStoredProcedureRequest( StoredProcedureRequest storedProcedureRequest )
    {
        this.storedProcedureRequest = storedProcedureRequest;
    }


    /**
     * Get the current parameter
     * 
     * @return The current parameter
     */
    public StoredProcedureParameter getCurrentParameter()
    {
        return currentParameter;
    }


    /**
     * Sets the current parameter
     * 
     * @param currentParameter The current parameter
     */
    public void setCurrentParameter( StoredProcedureParameter currentParameter )
    {
        this.currentParameter = currentParameter;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void clean()
    {
        super.clean();
        storedProcedureRequest = null;
        currentParameter = null;
    }
}
