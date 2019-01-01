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


import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.ber.AbstractContainer;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.ldap.codec.LdapMessageGrammar;
import org.apache.directory.api.ldap.codec.LdapStatesEnum;
import org.apache.directory.api.ldap.codec.search.ConnectorFilter;
import org.apache.directory.api.ldap.codec.search.Filter;
import org.apache.directory.api.ldap.codec.search.PresentFilter;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.ResultResponse;


/**
 * The LdapMessage container stores all the messages decoded by the Asn1Decoder.
 * When dealing with an encoding PDU, we will obtain a LdapMessage in the
 * container.
 *
 * @param <E> The decorated message
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class LdapMessageContainer<E extends Message> extends AbstractContainer
{
    /** The Message being decoded */
    private E message;

    /** checks if attribute is binary */
    private BinaryAttributeDetector binaryAttributeDetector;

    /** The message ID */
    private int messageId;

    /** The current control */
    private Control currentControl;
    
    /** The current control factory, if any */
    private ControlFactory<?> controlFactory;
    
    /** The current Intermediate response factory */
    private IntermediateOperationFactory intermediateFactory;
    
    /** The current Extended operation factory */
    private ExtendedOperationFactory extendedFactory;

    /** The codec service */
    private final LdapApiService codec;
    
    /** The current LdapResult for a response */
    private LdapResult ldapResult;
    
    /** The current attribute being decoded */
    private Attribute currentAttribute;

    /** A local storage for the MODIFY operation */
    private Modification currentModification;
    
    /** The SearchRequest TLV id */
    private int tlvId;

    /** A temporary storage for a terminal Filter */
    private Filter terminalFilter;

    /** The current filter. This is used while decoding a PDU */
    private Filter currentFilter;

    /** The global filter. This is used while decoding a PDU */
    private Filter topFilter;


    /**
     * Creates a new LdapMessageContainer object. We will store ten grammars,
     * it's enough ...
     * 
     * @param codec The LDAP service instance
     */
    public LdapMessageContainer( LdapApiService codec )
    {
        this( codec, new DefaultConfigurableBinaryAttributeDetector() );
    }


    /**
     * Creates a new LdapMessageContainer object. 
     *
     * @param codec The LDAP service instance
     * @param binaryAttributeDetector checks if an attribute is binary
     */
    public LdapMessageContainer( LdapApiService codec, BinaryAttributeDetector binaryAttributeDetector )
    {
        super();
        this.codec = codec;
        setGrammar( LdapMessageGrammar.getInstance() );
        this.binaryAttributeDetector = binaryAttributeDetector;
        setTransition( LdapStatesEnum.START_STATE );
    }


    /**
     * Gets the {@link LdapApiService} associated with this Container.
     *
     * @return The LDAP service instance
     */
    public LdapApiService getLdapCodecService()
    {
        return codec;
    }


    /**
     * @return Returns the ldapMessage.
     */
    public E getMessage()
    {
        return message;
    }


    /**
     * Set a Message Object into the container. It will be completed by the
     * ldapDecoder.
     *
     * @param message The message to set.
     */
    public void setMessage( E message )
    {
        this.message = message;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void clean()
    {
        super.clean();

        messageId = -1;
        tlvId = -1;
        message = null;
        ldapResult = null;
        currentControl = null;
        currentAttribute = null;
        currentFilter = null;
        terminalFilter = null;
        topFilter = null;
        controlFactory = null;
        intermediateFactory = null;
        extendedFactory = null;
        setDecodedBytes( 0 );
    }


    /**
     * @return Returns true if the attribute is binary.
     * @param id checks if an attribute id is binary
     */
    public boolean isBinary( String id )
    {
        return binaryAttributeDetector.isBinary( id );
    }


    /**
     * @return The message ID
     */
    public int getMessageId()
    {
        return messageId;
    }


    /**
     * Set the message ID
     * @param messageId the id of the message
     */
    public void setMessageId( int messageId )
    {
        this.messageId = messageId;
    }


    /**
     * @return the current control being created
     */
    public Control getCurrentControl()
    {
        return currentControl;
    }


    /**
     * Store a newly created control
     * @param currentControl The control to store
     */
    public void setCurrentControl( Control currentControl )
    {
        this.currentControl = currentControl;
    }


    /**
     * Sets the binary attribute detector
     * 
     * @param binaryAttributeDetector the binary attribute detector
     */
    public void setBinaryAttributeDetector( BinaryAttributeDetector binaryAttributeDetector )
    {
        this.binaryAttributeDetector = binaryAttributeDetector;
    }


    /**
     * @return the binary attribute detector
     */
    public BinaryAttributeDetector getBinaryAttributeDetector()
    {
        return binaryAttributeDetector;
    }


    /**
     * @return the ldapResult
     */
    public LdapResult getLdapResult()
    {
        return ldapResult;
    }


    /**
     * @param ldapResult the ldapResult to set
     */
    public void setLdapResult( LdapResult ldapResult )
    {
        this.ldapResult = ldapResult;
    }


    /**
     * @return the controlFactory
     */
    public ControlFactory<?> getControlFactory()
    {
        return controlFactory;
    }


    /**
     * @param controlFactory the controlFactory to set
     */
    public void setControlFactory( ControlFactory<?> controlFactory )
    {
        this.controlFactory = controlFactory;
    }


    /**
     * @return the currentAttribute
     */
    public Attribute getCurrentAttribute()
    {
        return currentAttribute;
    }


    /**
     * @param currentAttribute the currentAttribute to set
     */
    public void setCurrentAttribute( Attribute currentAttribute )
    {
        this.currentAttribute = currentAttribute;
    }


    /**
     * @return the currentModification
     */
    public Modification getCurrentModification()
    {
        return currentModification;
    }


    /**
     * @param currentModification the currentModification to set
     */
    public void setCurrentModification( Modification currentModification )
    {
        this.currentModification = currentModification;
    }


    /**
     * Set the SearchRequest PDU TLV's Id
     * @param tlvId The TLV id
     */
    public void setTlvId( int tlvId )
    {
        this.tlvId = tlvId;
    }


    /**
     * @return the terminalFilter
     */
    public Filter getTerminalFilter()
    {
        return terminalFilter;
    }


    /**
     * @param terminalFilter the terminalFilter to set
     */
    public void setTerminalFilter( Filter terminalFilter )
    {
        this.terminalFilter = terminalFilter;
    }


    /**
     * @return the currentFilter
     */
    public Filter getCurrentFilter()
    {
        return currentFilter;
    }


    /**
     * @param currentFilter the currentFilter to set
     */
    public void setCurrentFilter( Filter currentFilter )
    {
        this.currentFilter = currentFilter;
    }


    /**
     * Add a current filter. We have two cases :
     * - there is no previous current filter : the filter
     * is the top level filter
     * - there is a previous current filter : the filter is added
     * to the currentFilter set, and the current filter is changed
     *
     * In any case, the previous current filter will always be a
     * ConnectorFilter when this method is called.
     *
     * @param localFilter The filter to set.
     * @throws DecoderException If the filter is invalid
     */
    public void addCurrentFilter( Filter localFilter ) throws DecoderException
    {
        if ( currentFilter != null )
        {
            // Ok, we have a parent. The new Filter will be added to
            // this parent, and will become the currentFilter if it's a connector.
            ( ( ConnectorFilter ) currentFilter ).addFilter( localFilter );
            localFilter.setParent( currentFilter, currentFilter.getTlvId() );

            if ( localFilter instanceof ConnectorFilter )
            {
                currentFilter = localFilter;
            }
        }
        else
        {
            // No parent. This Filter will become the root.
            currentFilter = localFilter;
            currentFilter.setParent( null, tlvId );
            topFilter = localFilter;
        }
    }


    /**
     * This method is used to clear the filter's stack for terminated elements. An element
     * is considered as terminated either if :
     *  - it's a final element (ie an element which cannot contains a Filter)
     *  - its current length equals its expected length.
     *
     * @param container The container being decoded
     */
    public void unstackFilters()
    {
        TLV tlv = getCurrentTLV();
        TLV localParent = tlv.getParent();
        Filter localFilter = terminalFilter;

        // The parent has been completed, so fold it
        while ( ( localParent != null ) && ( localParent.getExpectedLength() == 0 ) )
        {
            int parentTlvId = localFilter.getParent() != null ? localFilter.getParent().getTlvId() : localFilter
                .getParentTlvId();

            if ( localParent.getId() != parentTlvId )
            {
                localParent = localParent.getParent();
            }
            else
            {
                Filter filterParent = localFilter.getParent();

                // We have a special case with PresentFilter, which has not been
                // pushed on the stack, so we need to get its parent's parent
                if ( localFilter instanceof PresentFilter )
                {
                    if ( filterParent == null )
                    {
                        // We don't have parent, get out
                        break;
                    }

                    filterParent = filterParent.getParent();
                }
                else
                {
                    filterParent = filterParent.getParent();
                }

                if ( filterParent != null )
                {
                    // The parent is a filter ; it will become the new currentFilter
                    // and we will loop again.
                    localFilter = currentFilter;
                    currentFilter = filterParent;
                    localParent = localParent.getParent();
                }
                else
                {
                    // We can stop the recursion, we have reached the searchResult Object
                    break;
                }
            }
        }
    }
    
    
    /**
     * Copy the LdapResult element from a opaque response to a newly created 
     * extendedResponse
     *  
     * @param resultResponse The original response
     * @param extendedResponse The newly created ExtendedResponse
     */
    public static void copyLdapResult( ResultResponse resultResponse, ExtendedResponse extendedResponse )
    {
        extendedResponse.getLdapResult().setDiagnosticMessage( resultResponse.getLdapResult().getDiagnosticMessage() );
        extendedResponse.getLdapResult().setMatchedDn( resultResponse.getLdapResult().getMatchedDn() );
        extendedResponse.getLdapResult().setReferral( resultResponse.getLdapResult().getReferral() );
        extendedResponse.getLdapResult().setResultCode( resultResponse.getLdapResult().getResultCode() );
    }


    /**
     * @return the topFilter
     */
    public Filter getTopFilter()
    {
        return topFilter;
    }


    /**
     * @param topFilter the topFilter to set
     */
    public void setTopFilter( Filter topFilter )
    {
        this.topFilter = topFilter;
    }


    /**
     * @return the tlvId
     */
    public int getTlvId()
    {
        return tlvId;
    }


    /**
     * @return the intermediateFactory
     */
    public IntermediateOperationFactory getIntermediateFactory()
    {
        return intermediateFactory;
    }


    /**
     * @param intermediateFactory the intermediateFactory to set
     */
    public void setIntermediateFactory( IntermediateOperationFactory intermediateFactory )
    {
        this.intermediateFactory = intermediateFactory;
    }


    /**
     * @return the extendedFactory
     */
    public ExtendedOperationFactory getExtendedFactory()
    {
        return extendedFactory;
    }


    /**
     * @param extendedFactory the extendedFactory to set
     */
    public void setExtendedFactory( ExtendedOperationFactory extendedFactory )
    {
        this.extendedFactory = extendedFactory;
    }
}
