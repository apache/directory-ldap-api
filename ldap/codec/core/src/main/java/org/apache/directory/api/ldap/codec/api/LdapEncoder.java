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


import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.Map;

import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.asn1.util.Asn1Buffer;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.factory.AbandonRequestFactory;
import org.apache.directory.api.ldap.codec.factory.AddRequestFactory;
import org.apache.directory.api.ldap.codec.factory.AddResponseFactory;
import org.apache.directory.api.ldap.codec.factory.BindRequestFactory;
import org.apache.directory.api.ldap.codec.factory.BindResponseFactory;
import org.apache.directory.api.ldap.codec.factory.CompareRequestFactory;
import org.apache.directory.api.ldap.codec.factory.CompareResponseFactory;
import org.apache.directory.api.ldap.codec.factory.DeleteRequestFactory;
import org.apache.directory.api.ldap.codec.factory.DeleteResponseFactory;
import org.apache.directory.api.ldap.codec.factory.ExtendedRequestFactory;
import org.apache.directory.api.ldap.codec.factory.ExtendedResponseFactory;
import org.apache.directory.api.ldap.codec.factory.IntermediateResponseFactory;
import org.apache.directory.api.ldap.codec.factory.ModifyDnRequestFactory;
import org.apache.directory.api.ldap.codec.factory.ModifyDnResponseFactory;
import org.apache.directory.api.ldap.codec.factory.ModifyRequestFactory;
import org.apache.directory.api.ldap.codec.factory.ModifyResponseFactory;
import org.apache.directory.api.ldap.codec.factory.SearchRequestFactory;
import org.apache.directory.api.ldap.codec.factory.SearchResultDoneFactory;
import org.apache.directory.api.ldap.codec.factory.SearchResultEntryFactory;
import org.apache.directory.api.ldap.codec.factory.SearchResultReferenceFactory;
import org.apache.directory.api.ldap.codec.factory.UnbindRequestFactory;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.Request;


/**
 * LDAP BER encoder.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class LdapEncoder
{
    /**
     * Make this final class impossible to instaciate from teh outside
     */
    private LdapEncoder()
    {
        // Nothing to do
    }


    /**
     * Encode a control to a byte[]. The controls are encoded recursively, to start with the last
     * control first.
     * <br>
     * A control is encoded as:
     * <pre>
     * 0x30 LL
     *   0x04 LL abcd               control OID
     *   [0x01 0x01 0x00/0xFF]      control criticality
     *   [0x04 LL value]            control value
     * </pre>
     *
     *
     * @param buffer The buffer that will contain the encoded control
     * @param codec The LdapApiService instance 
     * @param controls The controls to encode
     * @param iterator The Iterator instance we are processing
     * @param isRequest A flag set to <tt>true</tt> if the LdapMessage is a request
     * @throws EncoderException If the encoding failed
     */
    private static void encodeControls( Asn1Buffer buffer, LdapApiService codec,
        Map<String, Control> controls, Iterator<String> iterator, boolean isRequest ) throws EncoderException
    {
        if ( iterator.hasNext() )
        {
            // Get the Control from its OID
            Control control = controls.get( iterator.next() );

            // Encode the remaining controls recursively
            encodeControls( buffer, codec, controls, iterator, isRequest );

            // Fetch the control's factory from the LdapApiService
            ControlFactory<?> controlFactory;

            if ( isRequest )
            {
                controlFactory = codec.getRequestControlFactories().get( control.getOid() );
            }
            else
            {
                controlFactory = codec.getResponseControlFactories().get( control.getOid() );
            }

            if ( controlFactory == null )
            {
                throw new EncoderException( I18n.err( I18n.ERR_08002_CANNOT_FIND_CONTROL_FACTORY, control.getOid() ) );
            }

            int start = buffer.getPos();

            // the value, if any
            controlFactory.encodeValue( buffer, control );
            
            if ( buffer.getPos() != start )
            {
                // The control value sequence, as an OctetString
                BerValue.encodeSequence( buffer, ( byte ) UniversalTag.OCTET_STRING.getValue(), start );
            }

            // The criticality
            if ( control.isCritical() )
            {
                BerValue.encodeBoolean( buffer, control.isCritical() );
            }

            // The OID
            BerValue.encodeOctetString( buffer, control.getOid() );

            // The Control Sequence
            BerValue.encodeSequence( buffer, start );
        }
    }


    /**
     * Encode the protocolOp part of a message
     *
     * @param buffer The buffer that will contain the encoded control
     * @param codec The LdapApiService instance
     * @param message The message to encode
     */
    private static void encodeProtocolOp( Asn1Buffer buffer, LdapApiService codec, Message message )
    {
        switch ( message.getType() )
        {
            case ABANDON_REQUEST :
                AbandonRequestFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;

            case ADD_REQUEST :
                AddRequestFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;

            case ADD_RESPONSE:
                AddResponseFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;

            case BIND_REQUEST :
                BindRequestFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;

            case BIND_RESPONSE :
                BindResponseFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;

            case COMPARE_REQUEST :
                CompareRequestFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;

            case COMPARE_RESPONSE :
                CompareResponseFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;

            case DEL_REQUEST :
                DeleteRequestFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;

            case DEL_RESPONSE :
                DeleteResponseFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;
                
            case EXTENDED_REQUEST :
                ExtendedRequestFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;
                
            case EXTENDED_RESPONSE :
                ExtendedResponseFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;
                
            case INTERMEDIATE_RESPONSE :
                IntermediateResponseFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;

            case MODIFY_REQUEST :
                ModifyRequestFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;

            case MODIFY_RESPONSE :
                ModifyResponseFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;

            case MODIFYDN_REQUEST :
                ModifyDnRequestFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;

            case MODIFYDN_RESPONSE :
                ModifyDnResponseFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;

            case SEARCH_REQUEST :
                SearchRequestFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;

            case SEARCH_RESULT_DONE :
                SearchResultDoneFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;

            case SEARCH_RESULT_ENTRY :
                SearchResultEntryFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;

            case SEARCH_RESULT_REFERENCE :
                SearchResultReferenceFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;

            case UNBIND_REQUEST :
                UnbindRequestFactory.INSTANCE.encodeReverse( codec, buffer, message );
                return;

            default:
                // Nothing to do
        }
    }


    /**
     * Generate the PDU which contains the encoded object.
     *
     * The generation is done in two phases :
     * - first, we compute the length of each part and the
     * global PDU length
     * - second, we produce the PDU.
     *
     * <pre>
     * 0x30 L1
     *   |
     *   +--&gt; 0x02 L2 MessageId
     *   +--&gt; ProtocolOp
     *   +--&gt; Controls
     *
     * L2 = Length(MessageId)
     * L1 = Length(0x02) + Length(L2) + L2 + Length(ProtocolOp) + Length(Controls)
     * LdapMessageLength = Length(0x30) + Length(L1) + L1
     * </pre>
     *
     * @param buffer The Asn1Buffer instance in which we store the temporary result
     * @param codec The LdapApiService instance
     * @param message The message to encode
     * @return A ByteBuffer that contains the PDU
     * @throws EncoderException If anything goes wrong.
     */
    public static ByteBuffer encodeMessage( Asn1Buffer buffer, LdapApiService codec, Message message ) throws EncoderException
    {
        int start = buffer.getPos();

        // The controls, if any
        Map<String, Control> controls = message.getControls();

        if ( ( controls != null ) && ( controls.size() > 0 ) )
        {
            encodeControls( buffer, codec, controls, controls.keySet().iterator(), message instanceof Request );

            // The controls tag
            BerValue.encodeSequence( buffer, ( byte ) LdapCodecConstants.CONTROLS_TAG, start );
        }

        // The protocolOp part
        encodeProtocolOp( buffer, codec, message );

        // The message Id
        BerValue.encodeInteger( buffer, message.getMessageId() );

        // The LdapMessage Sequence
        BerValue.encodeSequence( buffer );

        return buffer.getBytes();
    }
}
