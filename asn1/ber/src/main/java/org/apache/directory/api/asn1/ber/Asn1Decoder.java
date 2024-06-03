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
package org.apache.directory.api.asn1.ber;


import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.TLVBerDecoderMBean;
import org.apache.directory.api.asn1.ber.tlv.TLVStateEnum;
import org.apache.directory.api.asn1.util.Asn1StringUtils;
import org.apache.directory.api.i18n.I18n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A BER TLV Tag component decoder. This decoder instantiate a Tag. The tag
 * won't be implementations should not copy the handle to the Tag object
 * delivered but should copy the data if they need it over the long term.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
*/
public final class Asn1Decoder implements TLVBerDecoderMBean
{
    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( Asn1Decoder.class );

    /** This flag is used to indicate that there are more bytes in the stream */
    private static final boolean MORE = true;

    /** This flag is used to indicate that there are no more bytes in the stream */
    private static final boolean END = false;

    /** Flag that is used to allow/disallow the indefinite form of Length */
    private boolean indefiniteLengthAllowed;

    /** The maximum number of bytes that could be used to encode the Length */
    private int maxLengthLength;

    /** The maximum number of bytes that could be used to encode the Tag */
    private int maxTagLength;


    /**
     * A public constructor of an Asn1 Decoder.
     */
    private Asn1Decoder()
    {
        indefiniteLengthAllowed = false;
        maxLengthLength = 1;
        maxTagLength = 1;
    }


    /**
     * Treat the start of a TLV. It reads the tag and get its value.
     * 
     * @param stream The ByteBuffer containing the PDU to decode
     * @param container The container that stores the current state,
     * the result and other informations.
     * @return <code>true</code> if there are more bytes to read, <code>false
     * </code> otherwise
     */
    private static  boolean treatTagStartState( ByteBuffer stream, Asn1Container container )
    {
        if ( stream.hasRemaining() )
        {
            byte octet = stream.get();

            TLV tlv = new TLV( container.getNewTlvId() );
            tlv.setTag( octet );

            // Store the current TLV in the container.
            container.setCurrentTLV( tlv );

            // Create a link between the current TLV with its parent
            tlv.setParent( container.getParentTLV() );

            // Switch to the next state, which is the Length decoding
            container.setState( TLVStateEnum.LENGTH_STATE_START );

            if ( LOG.isDebugEnabled() )
            {
                byte tag = container.getCurrentTLV().getTag();
                LOG.debug( I18n.msg( I18n.MSG_01000_TAG_DECODED, Asn1StringUtils.dumpByte( tag ) ) );
            }

            return MORE;
        }
        else
        {
            // The stream has been exhausted
            return END;
        }
    }


    /**
     * Dump the current TLV tree
     * 
     * @param container The container
     */
    private static void dumpTLVTree( Asn1Container container )
    {
        StringBuilder sb = new StringBuilder();
        TLV current = container.getCurrentTLV();

        sb.append( "TLV" ).append( Asn1StringUtils.dumpByte( current.getTag() ) ).append( "(" ).append(
            current.getExpectedLength() ).append( ")" );

        current = current.getParent();

        while ( current != null )
        {
            sb.append( "-TLV" ).append( Asn1StringUtils.dumpByte( current.getTag() ) ).append( "(" ).append(
                current.getExpectedLength() ).append( ")" );
            current = current.getParent();
        }

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_01001_TLV_TREE, sb.toString() ) );
        }
    }


    /**
     * Check if the TLV tree is fully decoded
     * 
     * @param container The container
     * @return <code>true</code> if the TLV has been decoded
     */
    private static boolean isTLVDecoded( Asn1Container container )
    {
        TLV current = container.getCurrentTLV();
        TLV parent = current.getParent();

        while ( parent != null )
        {
            if ( parent.getExpectedLength() != 0 )
            {
                return false;
            }

            parent = parent.getParent();
        }

        BerValue value = current.getValue();

        if ( ( value != null ) && ( value.getData() != null ) )
        {
            return current.getExpectedLength() == value.getData().length;
        }
        else
        {
            return current.getExpectedLength() == 0;
        }
    }


    /**
     * Treat the Length start. The tag has been decoded, so we have to deal with
     * the LENGTH, which can be multi-bytes.
     * 
     * @param stream  The ByteBuffer containing the PDU to decode
     * @param container The container that stores the current state,
     * the result and other informations.
     * @return <code>true</code> if there are more bytes to read, <code>false
     * </code> otherwise
     * @throws DecoderException Thrown if anything went wrong
     */
    private static boolean treatLengthStartState( ByteBuffer stream, Asn1Container container ) throws DecoderException
    {
        if ( stream.hasRemaining() )
        {
            byte octet = stream.get();
            TLV tlv = container.getCurrentTLV();

            if ( ( octet & TLV.LENGTH_LONG_FORM ) == 0 )
            {
                // We don't have a long form. The Length of the Value part is
                // given by this byte.
                tlv.setLength( octet );
                tlv.setLengthNbBytes( 1 );

                container.setState( TLVStateEnum.LENGTH_STATE_END );
            }
            else if ( ( octet & TLV.LENGTH_EXTENSION_RESERVED ) != TLV.LENGTH_EXTENSION_RESERVED )
            {
                int expectedLength = octet & TLV.LENGTH_SHORT_MASK;

                if ( expectedLength > 4 )
                {
                    String msg = I18n.err( I18n.ERR_01000_LENGTH_OVERFLOW );
                    LOG.error( msg );
                    throw new DecoderException( msg );
                }

                tlv.setLength( 0 );
                tlv.setLengthNbBytes( 1 + expectedLength );
                tlv.setLengthBytesRead( 1 );
                container.setState( TLVStateEnum.LENGTH_STATE_PENDING );
            }
            else
            {
                String msg = I18n.err( I18n.ERR_01001_LENGTH_EXTENSION_RESERVED );
                LOG.error( msg );
                throw new DecoderException( msg );
            }

            return MORE;
        }
        else
        {
            return END;
        }
    }


    /**
     * This function is called when a Length is in the process of being decoded,
     * but the lack of bytes in the buffer stopped the process.
     * 
     * @param stream The ByteBuffer containing the PDU to decode
     * @param container The container that stores the current state,
     * the result and other informations.
     * @return <code>true</code> if there are more bytes to read, <code>false
     * </code> otherwise
     * @throws DecoderException Thrown if anything went wrong
     */
    private static boolean treatLengthPendingState( ByteBuffer stream, Asn1Container container ) throws DecoderException
    {
        if ( stream.hasRemaining() )
        {
            TLV tlv = container.getCurrentTLV();
            int length = tlv.getLength();

            while ( tlv.getLengthBytesRead() < tlv.getLengthNbBytes() )
            {
                byte octet = stream.get();

                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( I18n.msg( I18n.MSG_01002_CURRENT_BYTE, Asn1StringUtils.dumpByte( octet ) ) );
                }

                tlv.incLengthBytesRead();
                length = ( length << 8 ) | ( octet & 0x00FF );
                
                if ( length < 0 )
                {
                    String msg = I18n.err( I18n.ERR_01002_TLV_NULL );
                    LOG.error( msg );
                    throw new DecoderException( msg );
                }

                if ( !stream.hasRemaining() )
                {
                    tlv.setLength( length );

                    if ( tlv.getLengthBytesRead() < tlv.getLengthNbBytes() )
                    {
                        container.setState( TLVStateEnum.LENGTH_STATE_PENDING );
                        return END;
                    }
                    else
                    {
                        container.setState( TLVStateEnum.LENGTH_STATE_END );
                        return MORE;
                    }
                }
            }

            tlv.setLength( length );
            container.setState( TLVStateEnum.LENGTH_STATE_END );

            return MORE;
        }
        else
        {

            return END;
        }
    }


    /**
     * A debug function used to dump the expected length stack.
     * 
     * @param tlv The current TLV.
     * @return A string which represent the expected length stack.
     */
    private static String getParentLength( TLV tlv )
    {
        StringBuilder buffer = new StringBuilder();

        buffer.append( "TLV expected length stack : " );
        TLV currentTlv = tlv;

        while ( true )
        {
            if ( currentTlv == null )
            {
                buffer.append( " - null" );
                break;
            }
            else
            {
                buffer.append( " - " ).append( currentTlv.getExpectedLength() );
            }

            currentTlv = currentTlv.getParent();
        }

        return buffer.toString();
    }


    /**
     * The Length is fully decoded. We have to call an action to check the size.
     * 
     * @param container The container that stores the current state,
     * the result and other informations.
     * @throws DecoderException Thrown if anything went wrong
     */
    private static void treatLengthEndState( Asn1Container container ) throws DecoderException
    {
        TLV tlv = container.getCurrentTLV();

        if ( tlv == null )
        {
            String msg = I18n.err( I18n.ERR_01002_TLV_NULL );
            LOG.error( msg );
            throw new DecoderException( msg );
        }

        int length = tlv.getLength();
        
        // Check we arent above the MAX PDU
        if ( length > container.getMaxPDUSize() )
        {
            throw new DecoderException( I18n.err( I18n.ERR_01007_PDU_SIZE_TOO_LONG, length, container.getMaxPDUSize() ) );
        }

        // We will check the length here. What we must control is
        // that the enclosing constructed TLV expected length is not
        // exceeded by the current TLV.
        TLV parentTLV = container.getParentTLV();

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_01003_PARENT_LENGTH, getParentLength( parentTLV ) ) );
        }

        if ( parentTLV == null )
        {
            // This is the first TLV, so we can't check anything. We will
            // just store this TLV as the root of the PDU
            tlv.setExpectedLength( length );
            container.setParentTLV( tlv );

            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_01004_ROOT_TLV, Integer.valueOf( length ) ) );
            }
        }
        else
        {
            // We have a parent, so we will check that its expected length is
            // not exceeded.
            int expectedLength = parentTLV.getExpectedLength();
            int currentLength = tlv.getSize();

            if ( expectedLength < currentLength )
            {
                // The expected length is lower than the Value length of the
                // current TLV. This is an error...
                if ( LOG.isDebugEnabled() )
                {
                    LOG.debug( I18n.msg( I18n.MSG_01005_TLV, 
                                Integer.valueOf( expectedLength ), 
                                Integer.valueOf( currentLength ) ) );
                }
                
                throw new DecoderException( I18n.err( I18n.ERR_01003_VALUE_LENGTH_ABOVE_EXPECTED_LENGTH, Integer
                    .valueOf( currentLength ), Integer.valueOf( expectedLength ) ) );
            }

            // deal with the particular case where expected length equal
            // the current length, which means that the parentTLV has been
            // completed.
            if ( expectedLength == currentLength )
            {
                parentTLV.setExpectedLength( 0 );

                // We also have to check that the current TLV is a constructed
                // one.
                // In this case, we have to switch from this parent TLV
                // to the parent's parent TLV.
                if ( tlv.isConstructed() )
                {
                    // here, we also have another special case : a
                    // zero length TLV. We must then unstack all
                    // the parents which length is null.
                    if ( length == 0 )
                    {
                        // We will set the parent to the first parentTLV which
                        // expectedLength
                        // is not null, and it will become the new parent TLV
                        while ( parentTLV != null )
                        {
                            if ( parentTLV.getExpectedLength() != 0 )
                            {
                                // ok, we have an incomplete parent. we will
                                // stop the recursion right here
                                break;
                            }
                            else
                            {
                                parentTLV = parentTLV.getParent();
                            }
                        }

                        container.setParentTLV( parentTLV );
                    }
                    else
                    {
                        // The new Parent TLV is this Constructed TLV
                        container.setParentTLV( tlv );
                    }

                    tlv.setParent( parentTLV );
                    tlv.setExpectedLength( length );
                }
                else
                {
                    tlv.setExpectedLength( length );

                    // It's over, the parent TLV has been completed.
                    // Go back to the parent's parent TLV until we find
                    // a tlv which is not complete.
                    while ( parentTLV != null )
                    {
                        if ( parentTLV.getExpectedLength() != 0 )
                        {
                            // ok, we have an incomplete parent. we will
                            // stop the recursion right here
                            break;
                        }
                        else
                        {
                            parentTLV = parentTLV.getParent();
                        }
                    }

                    container.setParentTLV( parentTLV );
                }
            }
            else
            {
                // Renew the expected Length.
                parentTLV.setExpectedLength( expectedLength - currentLength );
                tlv.setExpectedLength( length );

                if ( tlv.isConstructed() )
                {
                    // We have a constructed tag, so we must switch the
                    // parentTLV
                    tlv.setParent( parentTLV );
                    container.setParentTLV( tlv );
                }
            }

        }

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_01006_LENGTH_DECODED, Integer.valueOf( length ) ) );
        }

        if ( length == 0 )
        {
            // The length is 0, so we can't expect a value.
            container.setState( TLVStateEnum.TLV_STATE_DONE );
        }
        else
        {
            // Go ahead and decode the value part
            container.setState( TLVStateEnum.VALUE_STATE_START );
        }
    }


    /**
     * Treat the Value part. We will distinguish two cases : - if the Tag is a
     * Primitive one, we will get the value. - if the Tag is a Constructed one,
     * nothing will be done.
     * 
     * @param stream The ByteBuffer containing the PDU to decode
     * @param container The container that stores the current state,
     * the result and other informations.
     * @return <code>true</code> if there are more bytes to read, <code>false
     * </code> otherwise
     */
    private static  boolean treatValueStartState( ByteBuffer stream, Asn1Container container )
    {
        TLV currentTlv = container.getCurrentTLV();

        if ( TLV.isConstructed( currentTlv.getTag() ) && !container.isGathering() )
        {
            container.setState( TLVStateEnum.TLV_STATE_DONE );

            return MORE;
        }
        else
        {
            int length = currentTlv.getLength();
            int nbBytes = stream.remaining();

            if ( nbBytes < length )
            {
                currentTlv.getValue().init( length );
                currentTlv.getValue().setData( stream );
                container.setState( TLVStateEnum.VALUE_STATE_PENDING );

                return END;
            }
            else
            {
                currentTlv.getValue().init( length );
                stream.get( currentTlv.getValue().getData(), 0, length );
                container.setState( TLVStateEnum.TLV_STATE_DONE );

                return MORE;
            }
        }
    }


    /**
     * Treat a pending Value when we get more bytes in the buffer.
     * 
     * @param stream The ByteBuffer containing the PDU to decode
     * @param container The container that stores the current state,
     * the result and other informations.
     * @return <code>MORE</code> if some bytes remain in the buffer when the
     * value has been decoded, <code>END</code> if whe still need to get some
     * more bytes.
     */
    private static boolean treatValuePendingState( ByteBuffer stream, Asn1Container container )
    {
        TLV currentTlv = container.getCurrentTLV();

        int length = currentTlv.getLength();
        int currentLength = currentTlv.getValue().getCurrentLength();
        int nbBytes = stream.remaining();

        if ( ( currentLength + nbBytes ) < length )
        {
            currentTlv.getValue().addData( stream );
            container.setState( TLVStateEnum.VALUE_STATE_PENDING );

            return END;
        }
        else
        {
            int remaining = length - currentLength;
            byte[] data = new byte[remaining];
            stream.get( data, 0, remaining );
            currentTlv.getValue().addData( data );
            container.setState( TLVStateEnum.TLV_STATE_DONE );

            return MORE;
        }
    }


    /**
     * When the TLV has been fully decoded, we have to execute the associated
     * action and switch to the next TLV, which will start with a Tag.
     * 
     * @param stream The ByteBuffer containing the PDU to decode
     * @param container The container that stores the current state,
     * the result and other informations.
     * @return <code>true</code> if there are more bytes to read, <code>false
     * </code> otherwise
     * @throws DecoderException Thrown if anything went wrong
     */
    @SuppressWarnings("unchecked")
    private static boolean treatTLVDoneState( ByteBuffer stream, Asn1Container container ) throws DecoderException
    {
        if ( LOG.isDebugEnabled() )
        {
            dumpTLVTree( container );
        }

        // First, we have to execute the associated action
        container.getGrammar().executeAction( container );

        // Check if the PDU has been fully decoded.
        if ( isTLVDecoded( container ) )
        {
            if ( container.getState() == TLVStateEnum.GRAMMAR_END )
            {
                // Change the state to DECODED
                container.setState( TLVStateEnum.PDU_DECODED );
            }
            else
            {
                if ( container.isGrammarEndAllowed() )
                {
                    // Change the state to DECODED
                    container.setState( TLVStateEnum.PDU_DECODED );
                }
                else
                {
                    LOG.error( I18n.err( I18n.ERR_01004_MORE_TLV_EXPECTED ) );
                    throw new DecoderException( I18n.err( I18n.ERR_01005_TRUNCATED_PDU ) );
                }
            }
        }
        else
        {
            // Then we switch to the Start tag state and free the current TLV
            container.setState( TLVStateEnum.TAG_STATE_START );
        }

        return stream.hasRemaining();
    }


    /**
     * The decoder main function. This is where we read bytes from the stream
     * and go through the automaton. It's an inifnite loop which stop when no
     * more bytes are to be read. It can occurs if the ByteBuffer is exhausted
     * or if the PDU has been fully decoded.
     * 
     * @param stream The ByteBuffer containing the PDU to decode
     * @param container The container that store the state, the result
     * and other elements.
     * @throws DecoderException Thrown if anything went wrong!
     */
    public static void decode( ByteBuffer stream, Asn1Container container ) throws DecoderException
    {
        /*
         * We have to deal with the current state. This is an infinite loop,
         * which will stop for any of these reasons :
         * - STATE_END has been reached (hopefully, the most frequent case)
         * - buffer is empty (it could happen)
         * - STATE_OVERFLOW : bad situation ! The PDU may be a
         * malevolous hand crafted ones, that try to "kill" our decoder. We
         * must log it with all information to track back this case, and punish
         * the guilty !
         */
        boolean hasRemaining = stream.hasRemaining();

        // Increment the PDU size counter.
        container.incrementDecodedBytes( stream.remaining() );

        if ( container.getDecodedBytes() > container.getMaxPDUSize() )
        {
            String message = I18n.err( I18n.ERR_01007_PDU_SIZE_TOO_LONG, container.getDecodedBytes(), container
                .getMaxPDUSize() );
            LOG.error( message );
            throw new DecoderException( message );
        }

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_01007_LINE_SEPARATOR1 ) );
            LOG.debug( I18n.msg( I18n.MSG_01011_DECODING_PDU ) );
            LOG.debug( I18n.msg( I18n.MSG_01008_LINE_SEPARATOR2 ) );
        }

        while ( hasRemaining )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_01012_STATE, container.getState() ) );

                if ( stream.hasRemaining() )
                {
                    byte octet = stream.get( stream.position() );

                    LOG.debug( I18n.msg( I18n.MSG_01013_CURRENT_BYTE, Asn1StringUtils.dumpByte( octet ) ) );
                }
                else
                {
                    LOG.debug( I18n.msg( I18n.MSG_01014_NO_MORE_BYTE ) );
                }
            }

            switch ( container.getState() )
            {
                case TAG_STATE_START:
                    // Reset the GrammarEnd flag first
                    container.setGrammarEndAllowed( false );
                    hasRemaining = treatTagStartState( stream, container );

                    break;

                case LENGTH_STATE_START:
                    hasRemaining = treatLengthStartState( stream, container );

                    break;

                case LENGTH_STATE_PENDING:
                    hasRemaining = treatLengthPendingState( stream, container );

                    break;

                case LENGTH_STATE_END:
                    treatLengthEndState( container );

                    break;

                case VALUE_STATE_START:
                    hasRemaining = treatValueStartState( stream, container );

                    break;

                case VALUE_STATE_PENDING:
                    hasRemaining = treatValuePendingState( stream, container );

                    break;

                case VALUE_STATE_END:
                    hasRemaining = stream.hasRemaining();

                    // Nothing to do. We will never reach this state
                    break;

                case TLV_STATE_DONE:
                    hasRemaining = treatTLVDoneState( stream, container );

                    break;

                case PDU_DECODED:
                    // We have to deal with the case where there are
                    // more bytes in the buffer, but the PDU has been decoded.
                    if ( LOG.isDebugEnabled() )
                    {
                        LOG.debug( I18n.err( I18n.ERR_01008_REMAINING_BYTES_FOR_DECODED_PDU ) );
                    }

                    hasRemaining = false;

                    break;

                default:
                    break;
            }
        }

        if ( LOG.isDebugEnabled() )
        {
            LOG.debug( I18n.msg( I18n.MSG_01009_LINE_SEPARATOR3 ) );

            if ( container.getState() == TLVStateEnum.PDU_DECODED )
            {
                if ( container.getCurrentTLV() != null )
                {
                    LOG.debug( I18n.msg( I18n.MSG_01015_STOP_DECODING, container.getCurrentTLV().toString() ) );
                }
                else
                {
                    LOG.debug( I18n.msg( I18n.MSG_01016_STOP_DECODING_NULL_TLV ) );
                }
            }
            else
            {
                if ( container.getCurrentTLV() != null )
                {
                    LOG.debug( I18n.msg( I18n.MSG_01017_END_DECODING, container.getCurrentTLV().toString() ) );
                }
                else
                {
                    LOG.debug( I18n.msg( I18n.MSG_01018_END_DECODING_NULL_TLV ) );
                }
            }

            LOG.debug( I18n.msg( I18n.MSG_01010_LINE_SEPARATOR4 ) );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getMaxLengthLength()
    {
        return maxLengthLength;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getMaxTagLength()
    {
        return maxTagLength;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isIndefiniteLengthAllowed()
    {

        return indefiniteLengthAllowed;
    }
}
