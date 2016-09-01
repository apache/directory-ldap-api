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
package org.apache.directory.api.dsmlv2.response;


import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.model.message.MessageTypeEnum;
import org.apache.directory.api.ldap.model.message.ModifyResponse;
import org.apache.directory.api.ldap.model.message.ModifyResponseImpl;
import org.dom4j.Element;
import org.dom4j.tree.DefaultElement;


/**
 * DSML Decorator for ModifyResponse
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ModifyResponseDsml extends AbstractResultResponseDsml<ModifyResponse>
    implements ModifyResponse
{
    private static final String MODIFY_RESPONSE_TAG = "modifyResponse";


    /**
     * Creates a new getDecoratedMessage() of ModifyResponseDsml.
     * 
     * @param codec The LDAP Service to use
     */
    public ModifyResponseDsml( LdapApiService codec )
    {
        super( codec, new ModifyResponseImpl() );
    }


    /**
     * Creates a new getDecoratedMessage() of ModifyResponseDsml.
     *
     * @param codec The LDAP Service to use
     * @param ldapMessage the message to decorate
     */
    public ModifyResponseDsml( LdapApiService codec, ModifyResponse ldapMessage )
    {
        super( codec, ldapMessage );
    }


    /**
     * {@inheritDoc}
     */
    public MessageTypeEnum getType()
    {
        return getDecorated().getType();
    }


    /**
     * {@inheritDoc}
     */
    public Element toDsml( Element root )
    {
        Element element = null;

        if ( root != null )
        {
            element = root.addElement( MODIFY_RESPONSE_TAG );
        }
        else
        {
            element = new DefaultElement( MODIFY_RESPONSE_TAG );
        }

        LdapResultDsml ldapResultDsml = new LdapResultDsml( getCodecService(),
            getDecorated().getLdapResult(), getDecorated() );
        ldapResultDsml.toDsml( element );
        return element;
    }
}
