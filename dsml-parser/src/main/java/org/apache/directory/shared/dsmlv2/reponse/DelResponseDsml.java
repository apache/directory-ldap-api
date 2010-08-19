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

package org.apache.directory.shared.dsmlv2.reponse;


import org.apache.directory.shared.ldap.codec.MessageTypeEnum;
import org.apache.directory.shared.ldap.message.DeleteResponse;
import org.apache.directory.shared.ldap.message.DeleteResponseImpl;
import org.dom4j.Element;


/**
 * DSML Decorator for DelResponse
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class DelResponseDsml extends AbstractResponseDsml
{
    /**
     * Creates a new instance of DelResponseDsml.
     */
    public DelResponseDsml()
    {
        super( new DeleteResponseImpl() );
    }


    /**
     * Creates a new instance of DelResponseDsml.
     *
     * @param ldapMessage
     *      the message to decorate
     */
    public DelResponseDsml( DeleteResponse ldapMessage )
    {
        super( ldapMessage );
    }


    /* (non-Javadoc)
     * @see org.apache.directory.shared.dsmlv2.reponse.LdapMessageDecorator#getType()
     */
    public MessageTypeEnum getType()
    {
        return instance.getType();
    }


    /* (non-Javadoc)
     * @see org.apache.directory.shared.dsmlv2.reponse.DsmlDecorator#toDsml(org.dom4j.Element)
     */
    public Element toDsml( Element root )
    {
        Element element = root.addElement( "delResponse" );

        LdapResultDsml ldapResultDsml = new LdapResultDsml( ( ( DeleteResponse ) instance ).getLdapResult(), instance );
        ldapResultDsml.toDsml( element );
        return element;
    }
}
