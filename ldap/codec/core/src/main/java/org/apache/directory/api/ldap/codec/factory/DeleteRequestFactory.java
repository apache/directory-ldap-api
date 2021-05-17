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
package org.apache.directory.api.ldap.codec.factory;

import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.message.DeleteRequest;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.util.Strings;

/**
 * The DeleteRequest factory.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class DeleteRequestFactory implements Messagefactory
{
    /** The static instance */
    public static final DeleteRequestFactory INSTANCE = new DeleteRequestFactory();

    private DeleteRequestFactory()
    {
        // Nothing to do
    }

    /**
     * Encode the DeleteRequest message to a PDU.
     * <br>
     * DelRequest :
     * <pre>
     * 0x4A LL entry DN
     * </pre>
     *
     * @param codec The LdapApiService instance
     * @param buffer The buffer where to put the PDU
     * @param message the DeleteRequest to encode
     */
    @Override
    public void encodeReverse( LdapApiService codec, Asn1Buffer buffer, Message message )
    {
        // The entry
        BerValue.encodeOctetString( buffer, LdapCodecConstants.DEL_REQUEST_TAG,
            Strings.getBytesUtf8( ( ( DeleteRequest ) message ).getName().getName() ) );
    }
}
