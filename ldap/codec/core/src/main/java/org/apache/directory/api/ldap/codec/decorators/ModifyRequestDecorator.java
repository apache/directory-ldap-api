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
package org.apache.directory.api.ldap.codec.decorators;


import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapCodecConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.name.Dn;


/**
 * A decorator for the ModifyRequest message
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ModifyRequestDecorator extends SingleReplyRequestDecorator<ModifyRequest>
    implements ModifyRequest
{
    /** The modify request length */
    private int modifyRequestLength;

    /** The changes length */
    private int changesLength;

    /** The list of all change lengths */
    private List<Integer> changeLength;

    /** The list of all the modification lengths */
    private List<Integer> modificationLength;

    /** The list of all the value lengths */
    private List<Integer> valuesLength;

    /** The current attribute being decoded */
    private Attribute currentAttribute;

    /** A local storage for the operation */
    private ModificationOperation currentOperation;


    /**
     * Makes a ModifyRequest encodable.
     *
     * @param codec The LDAP service instance
     * @param decoratedMessage the decorated ModifyRequest
     */
    public ModifyRequestDecorator( LdapApiService codec, ModifyRequest decoratedMessage )
    {
        super( codec, decoratedMessage );
    }


    /**
     * Store the current operation
     * 
     * @param currentOperation The currentOperation to set.
     */
    public void setCurrentOperation( int currentOperation )
    {
        this.currentOperation = ModificationOperation.getOperation( currentOperation );
    }


    /**
     * Add a new attributeTypeAndValue
     * 
     * @param type The attribute's name
     */
    public void addAttributeTypeAndValues( String type )
    {
        currentAttribute = new DefaultAttribute( type );

        Modification modification = new DefaultModification( currentOperation, currentAttribute );
        getDecorated().addModification( modification );
    }


    /**
     * @return the current attribute's type
     */
    public String getCurrentAttributeType()
    {
        return currentAttribute.getUpId();
    }


    /**
     * Add a new value to the current attribute
     * 
     * @param value The value to add
     * @throws LdapException If teh value is invalid
     */
    public void addAttributeValue( byte[] value ) throws LdapException
    {
        currentAttribute.add( value );
    }


    /**
     * Add a new value to the current attribute
     * 
     * @param value The value to add
     * @throws LdapException If teh value is invalid
     */
    public void addAttributeValue( String value ) throws LdapException
    {
        currentAttribute.add( value );
    }


    //-------------------------------------------------------------------------
    // The ModifyRequest methods
    //-------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public Dn getName()
    {
        return getDecorated().getName();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest setName( Dn name )
    {
        getDecorated().setName( name );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Collection<Modification> getModifications()
    {
        return getDecorated().getModifications();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest addModification( Modification mod )
    {
        getDecorated().addModification( mod );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest removeModification( Modification mod )
    {
        getDecorated().removeModification( mod );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest remove( String attributeName, String... attributeValue )
    {
        getDecorated().remove( attributeName, attributeValue );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest remove( String attributeName, byte[]... attributeValue )
    {
        getDecorated().remove( attributeName, attributeValue );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest remove( Attribute attr )
    {
        getDecorated().remove( attr );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest remove( String attributeName )
    {
        getDecorated().remove( attributeName );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest addModification( Attribute attr, ModificationOperation modOp )
    {
        getDecorated().addModification( attr, modOp );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest add( String attributeName, String... attributeValue )
    {
        getDecorated().add( attributeName, attributeValue );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest add( String attributeName, byte[]... attributeValue )
    {
        getDecorated().add( attributeName, attributeValue );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest add( Attribute attr )
    {
        getDecorated().add( attr );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest replace( String attributeName )
    {
        getDecorated().replace( attributeName );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest replace( String attributeName, String... attributeValue )
    {
        getDecorated().replace( attributeName, attributeValue );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    public ModifyRequest replace( String attributeName, byte[]... attributeValue )
    {
        getDecorated().replace( attributeName, attributeValue );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest replace( Attribute attr )
    {
        getDecorated().replace( attr );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest setMessageId( int messageId )
    {
        super.setMessageId( messageId );

        return this;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest addControl( Control control )
    {
        return ( ModifyRequest ) super.addControl( control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest addAllControls( Control[] controls )
    {
        return ( ModifyRequest ) super.addAllControls( controls );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ModifyRequest removeControl( Control control )
    {
        return ( ModifyRequest ) super.removeControl( control );
    }


    //-------------------------------------------------------------------------
    // The Decorator methods
    //-------------------------------------------------------------------------

    /**
     * Compute the ModifyRequest length 
     * <br>
     * ModifyRequest :
     * <pre>
     * 0x66 L1
     *  |
     *  +--&gt; 0x04 L2 object
     *  +--&gt; 0x30 L3 modifications
     *        |
     *        +--&gt; 0x30 L4-1 modification sequence
     *        |     |
     *        |     +--&gt; 0x0A 0x01 (0..2) operation
     *        |     +--&gt; 0x30 L5-1 modification
     *        |           |
     *        |           +--&gt; 0x04 L6-1 type
     *        |           +--&gt; 0x31 L7-1 vals
     *        |                 |
     *        |                 +--&gt; 0x04 L8-1-1 attributeValue
     *        |                 +--&gt; 0x04 L8-1-2 attributeValue
     *        |                 +--&gt; ...
     *        |                 +--&gt; 0x04 L8-1-i attributeValue
     *        |                 +--&gt; ...
     *        |                 +--&gt; 0x04 L8-1-n attributeValue
     *        |
     *        +--&gt; 0x30 L4-2 modification sequence
     *        .     |
     *        .     +--&gt; 0x0A 0x01 (0..2) operation
     *        .     +--&gt; 0x30 L5-2 modification
     *                    |
     *                    +--&gt; 0x04 L6-2 type
     *                    +--&gt; 0x31 L7-2 vals
     *                          |
     *                          +--&gt; 0x04 L8-2-1 attributeValue
     *                          +--&gt; 0x04 L8-2-2 attributeValue
     *                          +--&gt; ...
     *                          +--&gt; 0x04 L8-2-i attributeValue
     *                          +--&gt; ...
     *                          +--&gt; 0x04 L8-2-n attributeValue
     * </pre>
     */
    @Override
    public int computeLength()
    {
        // Initialized with name
        modifyRequestLength = 1 + TLV.getNbBytes( Dn.getNbBytes( getName() ) )
            + Dn.getNbBytes( getName() );

        // All the changes length
        changesLength = 0;

        Collection<Modification> modifications = getModifications();

        if ( ( modifications != null ) && ( !modifications.isEmpty() ) )
        {
            changeLength = new LinkedList<>();
            modificationLength = new LinkedList<>();
            valuesLength = new LinkedList<>();

            for ( Modification modification : modifications )
            {
                // Modification sequence length initialized with the operation
                int localModificationSequenceLength = 1 + 1 + 1;
                int localValuesLength = 0;

                // Modification length initialized with the type
                int typeLength = modification.getAttribute().getUpId().length();
                int localModificationLength = 1 + TLV.getNbBytes( typeLength ) + typeLength;

                // Get all the values
                if ( modification.getAttribute().size() != 0 )
                {
                    for ( Value<?> value : modification.getAttribute() )
                    {
                        localValuesLength += 1 + TLV.getNbBytes( value.getBytes().length ) + value.getBytes().length;
                    }
                }

                localModificationLength += 1 + TLV.getNbBytes( localValuesLength ) + localValuesLength;

                // Compute the modificationSequenceLength
                localModificationSequenceLength += 1 + TLV.getNbBytes( localModificationLength )
                    + localModificationLength;

                // Add the tag and the length
                changesLength += 1 + TLV.getNbBytes( localModificationSequenceLength )
                    + localModificationSequenceLength;

                // Store the arrays of values
                valuesLength.add( localValuesLength );
                modificationLength.add( localModificationLength );
                changeLength.add( localModificationSequenceLength );
            }

            // Add the modifications length to the modificationRequestLength
            modifyRequestLength += 1 + TLV.getNbBytes( changesLength ) + changesLength;
        }

        return 1 + TLV.getNbBytes( modifyRequestLength ) + modifyRequestLength;
    }


    /**
     * Encode the ModifyRequest message to a PDU. 
     * <br>
     * ModifyRequest : 
     * <pre>
     * 0x66 LL
     *   0x04 LL object
     *   0x30 LL modifiations
     *     0x30 LL modification sequence
     *       0x0A 0x01 operation
     *       0x30 LL modification
     *         0x04 LL type
     *         0x31 LL vals
     *           0x04 LL attributeValue
     *           ... 
     *           0x04 LL attributeValue
     *     ... 
     *     0x30 LL modification sequence
     *       0x0A 0x01 operation
     *       0x30 LL modification
     *         0x04 LL type
     *         0x31 LL vals
     *           0x04 LL attributeValue
     *           ... 
     *           0x04 LL attributeValue
     * </pre>
     * 
     * @param buffer The buffer where to put the PDU
     * @return The PDU.
     */
    @Override
    public ByteBuffer encode( ByteBuffer buffer ) throws EncoderException
    {
        try
        {
            // The AddRequest Tag
            buffer.put( LdapCodecConstants.MODIFY_REQUEST_TAG );
            buffer.put( TLV.getBytes( modifyRequestLength ) );

            // The entry
            BerValue.encode( buffer, Dn.getBytes( getName() ) );

            // The modifications sequence
            buffer.put( UniversalTag.SEQUENCE.getValue() );
            buffer.put( TLV.getBytes( changesLength ) );

            // The modifications list
            Collection<Modification> modifications = getModifications();

            if ( ( modifications != null ) && ( !modifications.isEmpty() ) )
            {
                int modificationNumber = 0;

                // Compute the modifications length
                for ( Modification modification : modifications )
                {
                    // The modification sequence
                    buffer.put( UniversalTag.SEQUENCE.getValue() );
                    int localModificationSequenceLength = changeLength.get( modificationNumber );
                    buffer.put( TLV.getBytes( localModificationSequenceLength ) );

                    // The operation. The value has to be changed, it's not
                    // the same value in DirContext and in RFC 2251.
                    buffer.put( UniversalTag.ENUMERATED.getValue() );
                    buffer.put( ( byte ) 1 );
                    buffer.put( ( byte ) modification.getOperation().getValue() );

                    // The modification
                    buffer.put( UniversalTag.SEQUENCE.getValue() );
                    int localModificationLength = modificationLength.get( modificationNumber );
                    buffer.put( TLV.getBytes( localModificationLength ) );

                    // The modification type
                    BerValue.encode( buffer, modification.getAttribute().getUpId() );

                    // The values
                    buffer.put( UniversalTag.SET.getValue() );
                    int localValuesLength = valuesLength.get( modificationNumber );
                    buffer.put( TLV.getBytes( localValuesLength ) );

                    if ( modification.getAttribute().size() != 0 )
                    {
                        for ( org.apache.directory.api.ldap.model.entry.Value<?> value : modification.getAttribute() )
                        {
                            if ( value.isHumanReadable() )
                            {
                                BerValue.encode( buffer, value.getString() );
                            }
                            else
                            {
                                BerValue.encode( buffer, value.getBytes() );
                            }
                        }
                    }

                    // Go to the next modification number
                    modificationNumber++;
                }
            }
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_04005 ), boe );
        }

        return buffer;
    }
}
