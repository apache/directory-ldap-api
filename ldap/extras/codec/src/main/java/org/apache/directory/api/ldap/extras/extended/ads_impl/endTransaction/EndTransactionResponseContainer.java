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
package org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction;


import java.nio.ByteBuffer;
import java.util.List;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.asn1.ber.Asn1Decoder;
import org.apache.directory.api.asn1.ber.tlv.TLVStateEnum;
import org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction.controls.ControlsContainer;
import org.apache.directory.api.ldap.extras.extended.ads_impl.endTransaction.controls.ControlsStates;
import org.apache.directory.api.ldap.model.message.Control;


/**
 * A container for EndTransactionResponse codec.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class EndTransactionResponseContainer extends AbstractContainer
{
    /** EndTransactionResponse decorator*/
    private EndTransactionResponseDecorator endTransactionResponse;
    
    private static final Asn1Decoder DECODER = new Asn1Decoder();

    /**
     * Creates a new EndTransactionResponseContainer object. We will store one
     * grammar, it's enough ...
     */
    public EndTransactionResponseContainer()
    {
        super();
        setGrammar( EndTransactionResponseGrammar.getInstance() );
        setTransition( EndTransactionResponseStates.START_STATE );
    }


    /**
     * @return Returns the EndTransactionResponse instance.
     */
    public EndTransactionResponseDecorator getEndTransactionResponse()
    {
        return endTransactionResponse;
    }


    /**
     * Set a EndTransactionResponse Object into the container. It will be completed by
     * the ldapDecoder.
     * 
     * @param endTransactionResponseDecorator the EndTransactionResponse to set.
     */
    public void setEndTransactionResponse( EndTransactionResponseDecorator endTransactionResponseDecorator )
    {
        this.endTransactionResponse = endTransactionResponseDecorator;
    }


    /**
     * Clean the container for the next decoding.
     */
    @Override
    public void clean()
    {
        super.clean();
        endTransactionResponse = null;
    }
    
    
    /**
     * Decodes raw ASN.1 encoded bytes into an Asn1Object for the controls.
     * 
     * @param controlsBytes the encoded controls bytes
     * @return the decoded controls
     * @throws DecoderException if anything goes wrong
     */
    public static List<Control> decode( byte[] controlsBytes ) throws DecoderException
    {
        ByteBuffer bb = ByteBuffer.wrap( controlsBytes );
        ControlsContainer container = new ControlsContainer();
        
        // Loop on all the contained controls
        while ( bb.hasRemaining() )
        {
            DECODER.decode( bb, container );
            container.setState( TLVStateEnum.TAG_STATE_START );
            container.setTransition( ControlsStates.START_STATE );
        }
        
        return container.getControls();
    }
}
