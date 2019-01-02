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
package org.apache.directory.api.ldap.codec.api;


import java.io.InputStream;
import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.ber.tlv.TLVStateEnum;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.message.Message;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The LdapDecoder decodes ASN.1 BER encoded PDUs into LDAP messages
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapDecoder
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( LdapDecoder.class );

    /** The name of the LdapSession's attribute for the LDAP container used during the decoding */
    public static final String MESSAGE_CONTAINER_ATTR = "LDAP-container";

    /** The maximum PDU size, stored into the LDAPSession's attribute */
    public static final String MAX_PDU_SIZE_ATTR = "LDAP-maxPduSize";


    /**
     * Creates an instance of a Ldap Decoder implementation.
     */
    public LdapDecoder()
    {
    }


    /**
     * Decodes a PDU from an input stream into a Ldap message container. We can only
     * decode one complete message.
     *
     * @param in The input stream to read and decode PDU bytes from
     * @param container The LdapMessageContainer containing the message to decode
     * @return return The decoded message
     * @throws DecoderException If the decoding failed
     */
    public Message decode( InputStream in, LdapMessageContainer<? extends Message> container )
        throws DecoderException
    {
        try
        {
            int amount;

            while ( in.available() > 0 )
            {
                byte[] buf = new byte[in.available()];

                amount = in.read( buf );
                
                if ( amount == -1 )
                {
                    break;
                }

                Asn1Decoder.decode( ByteBuffer.wrap( buf, 0, amount ), container );
            }
        }
        catch ( Exception e )
        {
            String message = I18n.err( I18n.ERR_05204_LDAP_DECODER_FAILURE, e.getLocalizedMessage() );
            LOG.error( message );
            throw new DecoderException( message, e );
        }

        if ( container.getState() == TLVStateEnum.PDU_DECODED )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_5200_DECODED_LDAP_MESSAGE, container ) );
            }

            return container.getMessage();
        }
        else
        {
            LOG.error( I18n.err( I18n.ERR_05205_PDU_DOES_NOT_CONTAIN_ENOUGH_DATA ) );
            throw new DecoderException( I18n.err( I18n.ERR_05206_INPUT_STREAM_TOO_SHORT_PDU ) );
        }
    }
}
