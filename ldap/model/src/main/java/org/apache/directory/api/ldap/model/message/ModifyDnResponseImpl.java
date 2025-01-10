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
package org.apache.directory.api.ldap.model.message;


/**
 * ModifyDnResponse implementation
 * 
 * @author <a href="mailto:dev@directory.apache.org"> Apache Directory Project</a>
 */
public class ModifyDnResponseImpl extends AbstractResultResponse implements ModifyDnResponse
{
    /**
     * Creates a ModifyDnResponse as a reply to an ModifyDnRequest.
     */
    public ModifyDnResponseImpl()
    {
        super( -1, MessageTypeEnum.MODIFYDN_RESPONSE );
    }


    /**
     * Creates a ModifyDnResponse as a reply to an ModifyDnRequest.
     * 
     * @param id the sequence if of this response
     */
    public ModifyDnResponseImpl( final int id )
    {
        super( id, MessageTypeEnum.MODIFYDN_RESPONSE );
    }


    /**
     * Get a String representation of a ModifyDNResponse
     * 
     * @return A ModifyDNResponse String
     */
    @Override
    public String toString()
    {

        StringBuilder sb = new StringBuilder();

        sb.append( "    Modify Dn Response\n" );
        sb.append( super.toString() );

        return super.toString( sb.toString() );
    }
}
