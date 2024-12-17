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
package org.apache.directory.api.ldap.codec.protocol.mina;


import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapApiServiceFactory;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolCodecFactory;
import org.apache.mina.filter.codec.ProtocolDecoder;
import org.apache.mina.filter.codec.ProtocolEncoder;


/**
 * The factory used to create the LDAP encoder and decoder.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapProtocolCodecFactory implements ProtocolCodecFactory
{
    /** The statefull LDAP decoder */
    private LdapProtocolDecoder ldapDecoder;

    /** The statefull LDAP edcoder */
    private LdapProtocolEncoder ldapEncoder;
    
    
    /**
     * Creates a new instance of LdapProtocolCodecFactory.
     */
    public LdapProtocolCodecFactory() 
    {
        this( LdapApiServiceFactory.getSingleton() );
    }

    
    /**
     * 
     * Creates a new instance of LdapProtocolCodecFactory.
     *
     * @param ldapApiService The associated LdapApiService instance
     */
    public LdapProtocolCodecFactory( LdapApiService ldapApiService ) 
    {
        ldapDecoder = new LdapProtocolDecoder( ldapApiService );
        ldapEncoder = new LdapProtocolEncoder( ldapApiService );
    }
    

    /**
     * Get the LDAP decoder.
     *
     * @param ioSession the IO session
     * @return the decoder
     */
    @Override
    public ProtocolDecoder getDecoder( IoSession ioSession )
    {
        return ldapDecoder;
    }


    /**
     * Get the LDAP encoder.
     *
     * @param ioSession the IO session
     * @return the encoder
     */
    @Override
    public ProtocolEncoder getEncoder( IoSession ioSession )
    {
        return ldapEncoder;
    }
}
