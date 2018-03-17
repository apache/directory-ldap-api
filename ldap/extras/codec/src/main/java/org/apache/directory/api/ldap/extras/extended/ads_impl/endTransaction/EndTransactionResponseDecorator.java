/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction;


import java.nio.ByteBuffer;
import java.util.List;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.CodecControl;
import org.apache.directory.api.ldap.codec.decorators.ExtendedResponseDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapEncoder;
import org.apache.directory.api.ldap.extras.extended.endTransaction.EndTransactionResponse;
import org.apache.directory.api.ldap.extras.extended.endTransaction.UpdateControls;
import org.apache.directory.api.ldap.model.message.Control;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A Decorator for EndTransaction response.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class EndTransactionResponseDecorator extends ExtendedResponseDecorator<EndTransactionResponse> implements EndTransactionResponse
{
    private static final Logger LOG = LoggerFactory.getLogger( EndTransactionResponseDecorator.class );

    /** The endTransaction response */
    private EndTransactionResponse endTransactionResponse;

    /** The current UpdateControls */
    private UpdateControls currentUpdateControls;

    /** Stores the length of the request*/
    private int globalSequenceLength = 0;
    
    /** Stores the length of the updateControls part */
    private int updateSequenceLength = 0;
    
    /** Stores the length of updateControls */
    private int[] updateControlsLength;
    
    /** Stores the Controls global lengths */
    private int[] controlsLengths;
    
    /** The message controls' lengths */ 
    private int[][] controlLengths;

    /**
     * Creates a new instance of EndTransactionResponseDecorator.
     *
     * @param codec The LDAP service instance
     * @param decoratedMessage The decorated message
     */
    public EndTransactionResponseDecorator( LdapApiService codec, EndTransactionResponse decoratedMessage )
    {
        super( codec, decoratedMessage );
        endTransactionResponse = decoratedMessage;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setResponseValue( byte[] responseValue )
    {
        EndTransactionResponseDecoder decoder = new EndTransactionResponseDecoder();

        try
        {
            if ( responseValue != null )
            {
                endTransactionResponse = decoder.decode( responseValue );

                this.responseValue = new byte[responseValue.length];
                System.arraycopy( responseValue, 0, this.responseValue, 0, responseValue.length );
            }
            else
            {
                this.responseValue = null;
            }
        }
        catch ( DecoderException e )
        {
            LOG.error( I18n.err( I18n.ERR_04165_PAYLOAD_DECODING_ERROR ), e );
            throw new RuntimeException( e );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getFailedMessageId()
    {
        return endTransactionResponse.getFailedMessageId();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setFailedMessageId( int failedMessageId )
    {
        endTransactionResponse.setFailedMessageId( failedMessageId );
    }


    @Override
    public List<UpdateControls> getUpdateControls()
    {
        return endTransactionResponse.getUpdateControls();
    }

    
    /**
     * @return the currentUpdateControls
     */
    public UpdateControls getCurrentUpdateControls()
    {
        return currentUpdateControls;
    }

    
    /**
     * @param currentUpdateControls the currentUpdateControls to set
     */
    public void setCurrentControls( UpdateControls currentUpdateControls )
    {
        this.currentUpdateControls = currentUpdateControls;
    }


    /**
     * Compute the EndTransactionResponse extended operation length
     * <pre>
     * 0x30 L1 
     *   | 
     *  [+-- 0x02 L2 failed message ID] 
     *  [+-- 0x30 L3 updateControls SEQUENCE OF
     *         |
     *         +-- 0x30 L4 updateControls SEQUENCE
     *               |
     *               +-- 0x02 L5 messageID
     *               +-- <controls>]
     *               
     * </pre>
     */
    /* No qualifier */int computeLengthInternal()
    {
        globalSequenceLength = 0;
        
        if ( endTransactionResponse.getFailedMessageId() >= 0 )
        {
            // We have had a failure, there is no updateControls just the failed MessageID
            globalSequenceLength = 1 + 1 + BerValue.getNbBytes( endTransactionResponse.getFailedMessageId() );
            
            // The message ID length is always below 128, so we only need 1 byte for the global length
            return 1 + 1 + globalSequenceLength;
        }
        else
        {
            // If it's a success, we won't have a messageId, just update controls (if any)
            int updateControlsSize = getUpdateControls().size();
            
            if ( updateControlsSize > 0 )
            {
                updateControlsLength = new int[updateControlsSize];
                controlsLengths = new int[updateControlsSize];
                controlLengths = new int[updateControlsSize][];
                int messageControlsCount = 0;
                updateSequenceLength = 0;
                
                // Ok, process the updateControls
                for ( UpdateControls updateControls : getUpdateControls() )
                {
                    // The message ID, 0x02 LL and the ID
                    updateControlsLength[messageControlsCount] = 1 + 1 + BerValue.getNbBytes( updateControls.getMessageId() );
                    
                    // The controls
                    int controlNumber = updateControls.getControls().size();
                    
                    if ( controlNumber > 0 )
                    { 
                        int controlCount = 0;
                        controlLengths[messageControlsCount] = new int[controlNumber];
                        
                        for ( Control control : updateControls.getControls() )
                        {
                            controlLengths[messageControlsCount][controlCount] = LdapEncoder.computeControlLength( control );
                            controlsLengths[messageControlsCount] +=  1 + TLV.getNbBytes( controlLengths[messageControlsCount][controlCount] ) + controlLengths[messageControlsCount][controlCount];
                            controlCount++;
                        }
                        
                        int controlsLength = controlsLengths[messageControlsCount];
                        updateControlsLength[messageControlsCount] +=  1 + TLV.getNbBytes( controlsLength ) + controlsLength;
                    }
                    
                    updateSequenceLength += 1 + TLV.getNbBytes( updateControlsLength[messageControlsCount] ) 
                        + updateControlsLength[messageControlsCount];

                    messageControlsCount++;
                }
                
                globalSequenceLength = 1 + TLV.getNbBytes( updateSequenceLength ) + updateSequenceLength;
                
                return 1 + TLV.getNbBytes( globalSequenceLength ) + globalSequenceLength;
            }
            else
            {
                // No update control, return immediately
                return 0;
            }
        }
    }


    /**
     * Encodes the EndTransactionResponse extended operation.
     * 
     * @return A ByteBuffer that contains the encoded PDU
     * @throws org.apache.directory.api.asn1.EncoderException If anything goes wrong.
     */
    /* No qualifier */ByteBuffer encodeInternal() throws EncoderException
    {
        ByteBuffer bb = ByteBuffer.allocate( computeLengthInternal() );

        bb.put( UniversalTag.SEQUENCE.getValue() );
        bb.put( TLV.getBytes( globalSequenceLength ) );
        
        // The failed message id, if any
        if ( getFailedMessageId() >= 0 )
        {
            // We have had an error, just encode the messageId
            BerValue.encode( bb, getFailedMessageId() );
        }
        else
        {
            // No error, just updateControls
            bb.put( UniversalTag.SEQUENCE.getValue() );
            bb.put( TLV.getBytes( updateSequenceLength ) );

            int updateControlsNb = 0;
            
            for ( UpdateControls updateControls : getUpdateControls() )
            {
                // The updateControls length
                bb.put( UniversalTag.SEQUENCE.getValue() );
                bb.put( TLV.getBytes( updateControlsLength[updateControlsNb] ) );

                // The message ID
                BerValue.encode( bb, updateControls.getMessageId() );
                
                // The controls sequence
                bb.put( UniversalTag.SEQUENCE.getValue() );
                bb.put( TLV.getBytes( controlsLengths[updateControlsNb] ) );
                
                // The controls
                int controlNb = 0;

                for ( Control control : updateControls.getControls() )
                {
                    // The control SEQUENCE
                    bb.put( UniversalTag.SEQUENCE.getValue() );
                    bb.put( TLV.getBytes( controlLengths[updateControlsNb][controlNb] ) );
                    
                    // The control OID
                    BerValue.encode( bb, control.getOid() );

                    // The criticality, if true
                    if ( control.isCritical() )
                    {
                        BerValue.encode( bb,  true );
                    }
                    
                    // compute the value length 
                    int valueLength = ( ( CodecControl<?> ) control ).computeLength();
                    
                    if ( valueLength > 0 )
                    {
                        bb.put( UniversalTag.OCTET_STRING.getValue() );
                        bb.put( TLV.getBytes( valueLength ) );
                        ( ( CodecControl<?> ) control ).encode( bb );
                    }
                    
                    controlNb++;
                }
                
                updateControlsNb++;
            }
        }

        return bb;
    }
}
