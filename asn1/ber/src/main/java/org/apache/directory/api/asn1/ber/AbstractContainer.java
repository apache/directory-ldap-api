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
package org.apache.directory.api.asn1.ber;


import java.nio.ByteBuffer;

import org.apache.directory.api.asn1.ber.grammar.Grammar;
import org.apache.directory.api.asn1.ber.grammar.States;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.TLVStateEnum;


/**
 * This class is the abstract container used to store the current state of a PDU
 * being decoded. It also stores the grammars used to decode the PDU, and all
 * the informations needed to decode a PDU.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractContainer implements Asn1Container
{
    /** All the possible grammars */
    private Grammar<?> grammar;

    /** The current state of the decoding */
    private TLVStateEnum state;

    /** The current transition */
    private Enum<?> transition;

    /** The current TLV */
    private TLV tlv;

    /** The parent TLV */
    private TLV parentTLV;

    /** The grammar end transition flag */
    private boolean grammarEndAllowed;

    /** A counter for the decoded bytes */
    private int decodedBytes;

    /** The maximum allowed size for a PDU. Default to MAX int value */
    private int maxPDUSize = Integer.MAX_VALUE;

    /** The incremental id used to tag TLVs */
    private int id = 0;

    /** The Stream being decoded */
    private ByteBuffer stream;

    /** A flag telling if the Value should be accumulated before being decoded
     * for constructed types */
    private boolean gathering = false;


    /**
     * Creates a new instance of AbstractContainer with a starting state.
     *
     */
    protected AbstractContainer()
    {
        state = TLVStateEnum.TAG_STATE_START;
    }


    /**
     * Creates a new instance of AbstractContainer with a starting state.
     *
     * @param stream the buffer containing the data to decode
     */
    protected AbstractContainer( ByteBuffer stream )
    {
        state = TLVStateEnum.TAG_STATE_START;
        this.stream = stream;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Grammar<?> getGrammar()
    {
        return grammar;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setGrammar( Grammar<?> grammar )
    {
        this.grammar = grammar;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public TLVStateEnum getState()
    {
        return state;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setState( TLVStateEnum state )
    {
        this.state = state;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isGrammarEndAllowed()
    {
        return grammarEndAllowed;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setGrammarEndAllowed( boolean grammarEndAllowed )
    {
        this.grammarEndAllowed = grammarEndAllowed;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Enum<?> getTransition()
    {
        return transition;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setTransition( Enum<?> transition )
    {
        this.transition = transition;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setCurrentTLV( TLV currentTLV )
    {
        this.tlv = currentTLV;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public TLV getCurrentTLV()
    {
        return this.tlv;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public TLV getParentTLV()
    {
        return parentTLV;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setParentTLV( TLV parentTLV )
    {
        this.parentTLV = parentTLV;
    }


    /**
     * Clean the container for the next usage.
     */
    public void clean()
    {
        tlv = null;
        parentTLV = null;
        transition = ( ( States ) transition ).getStartState();
        state = TLVStateEnum.TAG_STATE_START;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getNewTlvId()
    {
        return id++;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getTlvId()
    {
        return tlv.getId();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getDecodedBytes()
    {
        return decodedBytes;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setDecodedBytes( int decodedBytes )
    {
        this.decodedBytes = decodedBytes;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void incrementDecodedBytes( int nb )
    {
        decodedBytes += nb;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int getMaxPDUSize()
    {
        return maxPDUSize;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setMaxPDUSize( int maxPDUSize )
    {
        if ( maxPDUSize > 0 )
        {
            this.maxPDUSize = maxPDUSize;
        }
        else
        {
            this.maxPDUSize = Integer.MAX_VALUE;
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ByteBuffer getStream()
    {
        return stream;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setStream( ByteBuffer stream )
    {
        this.stream = stream;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void rewind()
    {

        int start = stream.position() - 1 - tlv.getLengthNbBytes();
        stream.position( start );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void updateParent()
    {
        TLV parentTlv = tlv.getParent();

        while ( ( parentTlv != null ) && ( parentTlv.getExpectedLength() == 0 ) )
        {
            parentTlv = parentTlv.getParent();
        }

        this.parentTLV = parentTlv;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isGathering()
    {
        return gathering;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setGathering( boolean gathering )
    {
        this.gathering = gathering;
    }
}
