/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.directory.api.ldap.extras.controls.ad_impl;


import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.ldap.codec.api.ControlContainer;
import org.apache.directory.api.ldap.extras.controls.ad.AdDirSyncResponse;
import org.apache.directory.api.ldap.model.message.Control;


/**
 *
 * ASN.1 container for AD DirSyncResponse control.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class AdDirSyncResponseContainer extends AbstractContainer implements ControlContainer
{
    /** adDirSync */
    private Control control;

    /**
     * Creates a new AdDirSyncResponseControl object.
     *
     * @param control The AdDirSyncResponse control to store
     */
    public AdDirSyncResponseContainer( Control control )
    {
        super();
        this.control = control;
        setGrammar( AdDirSyncResponseGrammar.getInstance() );
        setTransition( AdDirSyncResponseStatesEnum.START_STATE );
    }


    /**
     * @return the AdDirSyncResponseControlCodec object
     */
    public AdDirSyncResponse getAdDirSyncResponseControl()
    {
        return ( AdDirSyncResponse ) control;
    }


    /**
     * Set a AdDirSyncResponse Control into the container. It will be completed
     * by the ldapDecoder.
     *
     * @param control the AdDirSyncResponse Control to set.
     */
    public void setControl( Control control )
    {
        this.control = control;
    }


    /**
     * clean the container
     */
    @Override
    public void clean()
    {
        super.clean();
        control = null;
    }
}
