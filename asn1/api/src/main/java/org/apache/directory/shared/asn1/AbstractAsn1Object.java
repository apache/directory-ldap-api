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
package org.apache.directory.shared.asn1;


import java.nio.ByteBuffer;

import org.apache.directory.shared.i18n.I18n;


/**
 * An abstract class which implements basic TLV operations.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public abstract class AbstractAsn1Object implements Asn1Object
{
    /** The object's current length. It is used while decoding PDUs */
    private int currentLength;

    /** The object's expected length. It is used while decoding PDUs */
    private int expectedLength;

    /** The encapsulating Object */
    private AbstractAsn1Object parent;

    /** The identifier of the associated TLV */
    private int tlvId;


    /**
     * Constructor associated with a TLV identifier. Used when
     * decoded a TLV, we create an association between the decode
     * Asn1Object and the TLV which is the encoded form.
     * 
     * @param tlvId The TLV Id.
     */
    protected AbstractAsn1Object( int tlvId )
    {
        this.tlvId = tlvId;
    }


    /**
     * Default constructor. The TLV Id is set to -1. This constructor
     * is called when an Asn1Object is created to be encoded, not decoded.
     */
    protected AbstractAsn1Object()
    {
        this.tlvId = -1;
    }


    /**
     * {@inheritDoc}
     */
    public void addLength( int length ) throws DecoderException
    {
        currentLength += length;

        if ( currentLength > expectedLength )
        {
            throw new DecoderException( I18n.err( I18n.ERR_00041_CURRENT_LENGTH_EXCEED_EXPECTED_LENGTH ) );
        }
    }


    /**
     * {@inheritDoc}
     */
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        return null;
    }


    /**
     * {@inheritDoc}
     */
    public int getCurrentLength()
    {
        return currentLength;
    }


    /**
     * {@inheritDoc}
     */
    public void setCurrentLength( int currentLength )
    {
        this.currentLength = currentLength;
    }


    /**
     * {@inheritDoc}
     */
    public int getExpectedLength()
    {
        return expectedLength;
    }


    /**
     * {@inheritDoc}
     */
    public void setExpectedLength( int expectedLength )
    {
        this.expectedLength = expectedLength;
    }


    /**
     * {@inheritDoc}
     */
    public AbstractAsn1Object getParent()
    {
        return parent;
    }


    /**
     * Sets the parent
     * 
     * @param parent The parent to set.
     */
    public void setParent( AbstractAsn1Object parent )
    {
        this.parent = parent;
    }


    /**
     * @return The TLV identifier associated with this object
     */
    public int getTlvId()
    {
        return tlvId;
    }
}
