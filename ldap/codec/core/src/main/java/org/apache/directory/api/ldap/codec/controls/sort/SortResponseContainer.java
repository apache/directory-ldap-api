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
import org.apache.directory.api.ldap.model.message.controls.SortResponse;


/**
 * Container for SortResponseControl.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class SortResponseContainer extends AbstractContainer
{
    /** the decorator instance of sort response control */
    private SortResponseDecorator control;

    /** LDAP codec */
    private LdapApiService codec;


    /**
     * Creates a new instance of SortResponseContainer.
     *
     * @param codec the LDAP codec
     */
    public SortResponseContainer( LdapApiService codec )
    {
        super();
        this.codec = codec;
        setGrammar( SortResponseGrammar.getInstance() );
        setTransition( SortResponseStates.START_STATE );
    }


    /**
     * Creates a new instance of SortResponseContainer.
     *
     * @param codec the LDAP codec
     * @param control the sort response control
     */
    public SortResponseContainer( LdapApiService codec, SortResponse control )
    {
        this( codec );
        decorate( control );
    }


    /**
     * Decorate the SortResponse control
     * 
     * @param control The Sort Response control to decorate
     */
    public void decorate( SortResponse control )
    {
        if ( control instanceof SortResponseDecorator )
        {
            this.control = ( SortResponseDecorator ) control;
        }
        else
        {
            this.control = new SortResponseDecorator( codec, control );
        }
    }


    /**
     * @return the control
     */
    public SortResponseDecorator getControl()
    {
        return control;
    }


    /**
     * @param control the control to set
     */
    public void setControl( SortResponseDecorator control )
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
