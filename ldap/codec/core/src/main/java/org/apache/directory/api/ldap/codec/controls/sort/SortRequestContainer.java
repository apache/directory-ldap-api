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
package org.apache.directory.api.ldap.codec.controls.sort;


import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.message.controls.SortKey;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;


/**
 * Container for SortRequestControl.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SortRequestContainer extends AbstractContainer
{
    /** the sort request control decorator */
    private SortRequestDecorator control;

    /** the LDAP codec */
    private LdapApiService codec;

    /** current key that is being decoded */
    private SortKey currentKey;


    /**
     * Creates a new instance of SortRequestContainer.
     *
     * @param codec the LDAP codec
     */
    public SortRequestContainer( LdapApiService codec )
    {
        super();
        this.codec = codec;
        setGrammar( SortRequestGrammar.getInstance() );
        setTransition( SortRequestStates.START_STATE );
    }


    /**
     * Creates a new instance of SortRequestContainer.
     *
     * @param codec the LDAP codec
     * @param control the sort request control
     */
    public SortRequestContainer( LdapApiService codec, SortRequest control )
    {
        this( codec );
        decorate( control );
    }


    /**
     * Decorate a SortRequest control
     * 
     * @param control The control to decorate
     */
    public void decorate( SortRequest control )
    {
        if ( control instanceof SortRequestDecorator )
        {
            this.control = ( SortRequestDecorator ) control;
        }
        else
        {
            this.control = new SortRequestDecorator( codec, control );
        }
    }


    /**
     * @return the control
     */
    public SortRequestDecorator getControl()
    {
        return control;
    }


    /**
     * @param control the control to set
     */
    public void setControl( SortRequestDecorator control )
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
     * @return the currentKey
     */
    public SortKey getCurrentKey()
    {
        return currentKey;
    }


    /**
     * @param currentKey the currentKey to set
     */
    public void setCurrentKey( SortKey currentKey )
    {
        this.currentKey = currentKey;
    }

}
