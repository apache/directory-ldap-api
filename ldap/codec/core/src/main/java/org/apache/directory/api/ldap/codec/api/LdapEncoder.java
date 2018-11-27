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


import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
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
import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.util.Strings;


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
     * Compute the control's encoded length
     *
     * @param control The control to compute
     * @return the encoded control length
     */
    public static int computeControlLength( Control control )
    {
        // First, compute the control's value length
        int controlValueLength = ( ( CodecControl<?> ) control ).computeLength();

        // Now, compute the envelop length
        // The OID
        int oidLengh = Strings.getBytesUtf8( control.getOid() ).length;
        int controlLength = 1 + TLV.getNbBytes( oidLengh ) + oidLengh;

        // The criticality, only if true
        if ( control.isCritical() )
        {
            // Always 3 for a boolean
            controlLength += 1 + 1 + 1;
        }

        if ( controlValueLength != 0 )
        {
            controlLength += 1 + TLV.getNbBytes( controlValueLength ) + controlValueLength;
        }

        return controlLength;
    }


    /**
     * Encode a control to a byte[]
     *
     * @param buffer The buffer that will contain the encoded control
     * @param control The control to encode
     * @return The control encoded in a byte[]
     * @throws EncoderException If the encoding failed
     */
    public static ByteBuffer encodeControl( ByteBuffer buffer, Control control ) throws EncoderException
    {
        if ( buffer == null )
        {
            throw new EncoderException( I18n.err( I18n.ERR_08000_CANNOT_PUT_A_PDU_IN_NULL_BUFFER ) );
        }

        try
        {
            // The LdapMessage Sequence
            buffer.put( UniversalTag.SEQUENCE.getValue() );

            // The length has been calculated by the computeLength method
            int controlLength = computeControlLength( control );
            buffer.put( TLV.getBytes( controlLength ) );
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_08212_PDU_BUFFER_TOO_SMALL ), boe );
        }

        // The control type
        BerValue.encode( buffer, Strings.getBytesUtf8( control.getOid() ) );

        // The control criticality, if true
        if ( control.isCritical() )
        {
            BerValue.encode( buffer, control.isCritical() );
        }

        return buffer;
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
     * @param control The control to encode
     * @return The control encoded in a byte[]
     * @throws EncoderException If the encoding failed
     */
    private static void encodeControlsReverse( Asn1Buffer buffer, LdapApiService codec,
        Map<String, Control> controls, Iterator<String> iterator ) throws EncoderException
    {
        if ( iterator.hasNext() )
        {
            Control control = controls.get( iterator.next() );

            encodeControlsReverse( buffer, codec, controls, iterator );

            // Fetch the control's factory from the LdapApiService
            ControlFactory<?> controlFactory = codec.getControlFactories().get( control.getOid() );

            int start = buffer.getPos();

            // the value, if any
            controlFactory.encodeValue( buffer, control );

            // The criticality
            if ( control.isCritical() )
            {
                BerValue.encodeBoolean( buffer, control.isCritical() );
            }

            // The OID
            BerValue.encodeOctetString( buffer, Strings.getBytesUtf8( control.getOid() ) );

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
                AbandonRequestFactory.INSTANCE.encodeReverse( buffer, message );
                return;

            case ADD_REQUEST :
                AddRequestFactory.INSTANCE.encodeReverse( buffer, message );
                return;

            case ADD_RESPONSE:
                AddResponseFactory.INSTANCE.encodeReverse( buffer, message );
                return;

            case BIND_REQUEST :
                BindRequestFactory.INSTANCE.encodeReverse( buffer, message );
                return;

            case BIND_RESPONSE :
                BindResponseFactory.INSTANCE.encodeReverse( buffer, message );
                return;

            case COMPARE_REQUEST :
                CompareRequestFactory.INSTANCE.encodeReverse( buffer, message );
                return;

            case COMPARE_RESPONSE :
                CompareResponseFactory.INSTANCE.encodeReverse( buffer, message );
                return;

            case DEL_REQUEST :
                DeleteRequestFactory.INSTANCE.encodeReverse( buffer, message );
                return;

            case DEL_RESPONSE :
                DeleteResponseFactory.INSTANCE.encodeReverse( buffer, message );
                return;

            case MODIFY_REQUEST :
                ModifyRequestFactory.INSTANCE.encodeReverse( buffer, message );
                return;

            case MODIFY_RESPONSE :
                ModifyResponseFactory.INSTANCE.encodeReverse( buffer, message );
                return;

            case MODIFYDN_REQUEST :
                ModifyDnRequestFactory.INSTANCE.encodeReverse( buffer, message );
                return;

            case MODIFYDN_RESPONSE :
                ModifyDnResponseFactory.INSTANCE.encodeReverse( buffer, message );
                return;

            case SEARCH_REQUEST :
                SearchRequestFactory.INSTANCE.encodeReverse( buffer, message );
                return;

            case SEARCH_RESULT_DONE :
                SearchResultDoneFactory.INSTANCE.encodeReverse( buffer, message );
                return;

            case SEARCH_RESULT_ENTRY :
                SearchResultEntryFactory.INSTANCE.encodeReverse( buffer, message );
                return;

            case SEARCH_RESULT_REFERENCE :
                SearchResultReferenceFactory.INSTANCE.encodeReverse( buffer, message );
                return;

            case UNBIND_REQUEST :
                UnbindRequestFactory.INSTANCE.encodeReverse( buffer, message );
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
     * @param codec The LdapApiService instance
     * @param message The message to encode
     * @return A ByteBuffer that contains the PDU
     * @throws EncoderException If anything goes wrong.
     */
    public static ByteBuffer encodeMessageReverse( Asn1Buffer buffer, LdapApiService codec, Message message ) throws EncoderException
    {
        // The controls, if any
        Map<String, Control> controls = message.getControls();

        if ( ( controls != null ) && ( controls.size() > 0 ) )
        {
            encodeControlsReverse( buffer, codec, message.getControls(), message.getControls().keySet().iterator() );
        }

        // The protocolOp part
        encodeProtocolOp( buffer, codec, message );

        // The message Id
        BerValue.encodeInteger( buffer, message.getMessageId() );

        // The LdapMessage Sequence
        BerValue.encodeSequence( buffer );

        return buffer.getBytes();
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
     * @param message The message to encode
     * @return A ByteBuffer that contains the PDU
     * @throws EncoderException If anything goes wrong.
     */
    public static ByteBuffer encodeMessage( LdapApiService codec, Message message ) throws EncoderException
    {
        AbstractMessageDecorator<? extends Message> decorator = AbstractMessageDecorator.getDecorator( codec, message );
        int length = computeMessageLength( decorator );

        ByteBuffer buffer = ByteBuffer.allocate( length );

        try
        {
            try
            {
                // The LdapMessage Sequence
                buffer.put( UniversalTag.SEQUENCE.getValue() );

                // The length has been calculated by the computeLength method
                buffer.put( TLV.getBytes( decorator.getMessageLength() ) );
            }
            catch ( BufferOverflowException boe )
            {
                throw new EncoderException( I18n.err( I18n.ERR_08212_PDU_BUFFER_TOO_SMALL ), boe );
            }

            // The message Id
            BerValue.encode( buffer, message.getMessageId() );

            // Add the protocolOp part
            decorator.encode( buffer );

            // Do the same thing for Controls, if any.
            Map<String, Control> controls = decorator.getControls();

            if ( ( controls != null ) && ( controls.size() > 0 ) )
            {
                // Encode the controls
                buffer.put( ( byte ) LdapCodecConstants.CONTROLS_TAG );
                buffer.put( TLV.getBytes( decorator.getControlsLength() ) );

                // Encode each control
                for ( Control control : controls.values() )
                {
                    encodeControl( buffer, control );

                    // The OctetString tag if the value is not null
                    int controlValueLength = ( ( CodecControl<?> ) control ).computeLength();

                    if ( controlValueLength > 0 )
                    {
                        buffer.put( UniversalTag.OCTET_STRING.getValue() );
                        buffer.put( TLV.getBytes( controlValueLength ) );

                        // And now, the value
                        ( ( org.apache.directory.api.ldap.codec.api.CodecControl<?> ) control ).encode( buffer );
                    }
                }
            }
        }
        catch ( EncoderException ee )
        {
            throw new MessageEncoderException( message.getMessageId(), ee.getMessage(), ee );
        }

        buffer.flip();

        return buffer;
    }


    /**
     * Compute the LdapMessage length LdapMessage :
     * <pre>
     * 0x30 L1
     *   |
     *   +--&gt; 0x02 0x0(1-4) [0..2^31-1] (MessageId)
     *   +--&gt; protocolOp
     *   [+--&gt; Controls]
     *
     * MessageId length = Length(0x02) + length(MessageId) + MessageId.length
     * L1 = length(ProtocolOp)
     * LdapMessage length = Length(0x30) + Length(L1) + MessageId length + L1
     * </pre>
     *
     * @param messageDecorator the decorated Message who's length is to be encoded
     * @return The message length
     */
    private static int computeMessageLength( AbstractMessageDecorator<? extends Message> messageDecorator )
    {
        // The length of the MessageId. It's the sum of
        // - the tag (0x02), 1 byte
        // - the length of the Id length, 1 byte
        // - the Id length, 1 to 4 bytes
        int ldapMessageLength = 1 + 1 + BerValue.getNbBytes( messageDecorator.getDecorated().getMessageId() );

        // Get the protocolOp length
        ldapMessageLength += messageDecorator.computeLength();

        Map<String, Control> controls = messageDecorator.getControls();

        // Do the same thing for Controls, if any.
        if ( !controls.isEmpty() )
        {
            // Controls :
            // 0xA0 L3
            //   |
            //   +--> 0x30 L4
            //   +--> 0x30 L5
            //   +--> ...
            //   +--> 0x30 Li
            //   +--> ...
            //   +--> 0x30 Ln
            //
            // L3 = Length(0x30) + Length(L5) + L5
            // + Length(0x30) + Length(L6) + L6
            // + ...
            // + Length(0x30) + Length(Li) + Li
            // + ...
            // + Length(0x30) + Length(Ln) + Ln
            //
            // LdapMessageLength = LdapMessageLength + Length(0x90)
            // + Length(L3) + L3
            int controlsSequenceLength = 0;

            // We may have more than one control. ControlsLength is L4.
            for ( Control control : controls.values() )
            {
                int controlLength = computeControlLength( control );

                controlsSequenceLength += 1 + TLV.getNbBytes( controlLength ) + controlLength;
            }

            // Computes the controls length
            // 1 + Length.getNbBytes( controlsSequenceLength ) + controlsSequenceLength
            messageDecorator.setControlsLength( controlsSequenceLength );

            // Now, add the tag and the length of the controls length
            ldapMessageLength += 1 + TLV.getNbBytes( controlsSequenceLength ) + controlsSequenceLength;
        }

        // Store the messageLength
        messageDecorator.setMessageLength( ldapMessageLength );

        // finally, calculate the global message size :
        // length(Tag) + Length(length) + length

        return 1 + ldapMessageLength + TLV.getNbBytes( ldapMessageLength );
    }


    /**
     * Encode the Referral message to a PDU.
     *
     * @param buffer The buffer where to put the PDU
     * @param referral The referral to encode
     * @exception EncoderException If the encoding failed
     */
    public static void encodeReferral( ByteBuffer buffer, Referral referral ) throws EncoderException
    {
        Collection<byte[]> ldapUrlsBytes = referral.getLdapUrlsBytes();

        if ( ( ldapUrlsBytes != null ) && ( !ldapUrlsBytes.isEmpty() ) )
        {
            // Encode the referrals sequence
            // The referrals length MUST have been computed before !
            buffer.put( ( byte ) LdapCodecConstants.LDAP_RESULT_REFERRAL_SEQUENCE_TAG );
            buffer.put( TLV.getBytes( referral.getReferralLength() ) );

            // Each referral
            for ( byte[] ldapUrlBytes : ldapUrlsBytes )
            {
                // Encode the current referral
                BerValue.encode( buffer, ldapUrlBytes );
            }
        }
    }


    /**
     * Compute the referral's encoded length
     * @param referral The referral to encode
     * @return The length of the encoded PDU
     */
    public static int computeReferralLength( Referral referral )
    {
        if ( referral != null )
        {
            Collection<String> ldapUrls = referral.getLdapUrls();

            if ( ( ldapUrls != null ) && ( !ldapUrls.isEmpty() ) )
            {
                int referralLength = 0;

                // Each referral
                for ( String ldapUrl : ldapUrls )
                {
                    byte[] ldapUrlBytes = Strings.getBytesUtf8( ldapUrl );
                    referralLength += 1 + TLV.getNbBytes( ldapUrlBytes.length ) + ldapUrlBytes.length;
                    referral.addLdapUrlBytes( ldapUrlBytes );
                }

                referral.setReferralLength( referralLength );

                return referralLength;
            }
            else
            {
                return 0;
            }
        }
        else
        {
            return 0;
        }
    }
}
