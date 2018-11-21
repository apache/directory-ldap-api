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
package org.apache.directory.api.ldap.codec.factory;

import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.message.Message;

/**
 * The UnbindRequest factory.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class UnbindRequestFactory implements Messagefactory
{
    /** The static instance */
    public static final UnbindRequestFactory INSTANCE = new UnbindRequestFactory();

    private UnbindRequestFactory()
    {
        // Nothing to do
    }

    /**
     * Encode the UnbindRequest message to a PDU.
     * <br>
     * UnbindRequest :
     * <pre>
     * 0x42 00
     * </pre>
     *
     * @param buffer The buffer where to put the PDU
     * @param message the UnbindRequest to encode
     */
    @Override
    public void encodeReverse( Asn1Buffer buffer, Message message )
    {
        // The OpCode
        BerValue.encodeSequence( buffer, LdapCodecConstants.UNBIND_REQUEST_TAG, buffer.getPos() );
    }
}
