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
 * ModifyResponse implementation
 * 
 */
public class ModifyResponseImpl extends AbstractResultResponse implements ModifyResponse
{
    /**
     * Creates a ModifyResponse as a reply to an ModifyRequest.
     */
    public ModifyResponseImpl()
    {
        super( -1, MessageTypeEnum.MODIFY_RESPONSE );
    }


    /**
     * Creates a ModifyResponse as a reply to an ModifyRequest.
     * 
     * @param id the sequence id for this response
     */
    public ModifyResponseImpl( final int id )
    {
        super( id, MessageTypeEnum.MODIFY_RESPONSE );
    }


    /**
     * Get a String representation of a ModifyResponse
     * 
     * @return A ModifyResponse String
     */
    @Override
    public String toString()
    {

        StringBuilder sb = new StringBuilder();

        sb.append( "    Modify Response\n" );
        sb.append( super.toString() );

        return super.toString( sb.toString() );
    }
}
