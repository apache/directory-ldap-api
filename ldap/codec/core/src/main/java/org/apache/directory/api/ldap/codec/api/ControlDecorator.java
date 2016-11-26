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


import org.apache.directory.api.asn1.Asn1Object;
import org.apache.directory.api.ldap.model.message.Control;


/**
 * Decorates Control objects by wrapping them, and enabling them as CodecControls
 * so the codec to store transient information associated with the Control in the
 * decorator while processing.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @param <E> The control type
 */
public abstract class ControlDecorator<E extends Control> implements CodecControl<E>, Asn1Object
{
    /** The decorated Control */
    private E decorated;

    /** The encoded value length */
    protected int valueLength;

    /** The encoded value of the control. */
    protected byte[] value;

    /** The codec service responsible for encoding decoding this object */
    private LdapApiService codec;


    /**
     * Creates a ControlDecorator to codec enable it.
     *
     * @param codec The Ldap service to use
     * @param decoratedControl The Control to decorate.
     */
    public ControlDecorator( LdapApiService codec, E decoratedControl )
    {
        this.decorated = decoratedControl;
        this.codec = codec;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public E getDecorated()
    {
        return decorated;
    }


    /**
     * Set the control to be decorated.
     * 
     * @param decorated The decorated control
     */
    public void setDecorated( E decorated )
    {
        this.decorated = decorated;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public LdapApiService getCodecService()
    {
        return codec;
    }


    // ------------------------------------------------------------------------
    // Control Methods
    // ------------------------------------------------------------------------

    /**
     * Get the control OID
     * 
     * @return A string which represent the control oid
     */
    @Override
    public String getOid()
    {
        return decorated.getOid();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasValue()
    {
        return value != null;
    }


    /**
     * Get the control value
     * 
     * @return The control value
     */
    @Override
    public byte[] getValue()
    {
        return value;
    }


    /**
     * Set the encoded control value
     * 
     * @param value The encoded control value to store
     */
    @Override
    public void setValue( byte[] value )
    {
        if ( value != null )
        {
            byte[] copy = new byte[value.length];
            System.arraycopy( value, 0, copy, 0, value.length );
            this.value = copy;
        }
        else
        {
            this.value = null;
        }
    }


    /**
     * Get the criticality
     * 
     * @return <code>true</code> if the criticality flag is true.
     */
    @Override
    public boolean isCritical()
    {
        return decorated.isCritical();
    }


    /**
     * Set the criticality
     * 
     * @param criticality The criticality value
     */
    @Override
    public void setCritical( boolean criticality )
    {
        decorated.setCritical( criticality );
    }


    // ------------------------------------------------------------------------
    // CodecControl Methods
    // ------------------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    @Override
    public int computeLength()
    {
        return 0;
    }


    // ------------------------------------------------------------------------
    // Object Method Overrides
    // ------------------------------------------------------------------------
    /**
     * @see Object#hashCode()
     */
    @Override
    public int hashCode()
    {
        return decorated.hashCode();
    }


    /**
     * @see Object#equals(Object)
     */
    @Override
    public boolean equals( Object o )
    {
        if ( decorated == null )
        {
            return o == null;
        }
        else
        {
            return decorated.equals( o );
        }
    }


    /**
     * Return a String representing a Control
     */
    @Override
    public String toString()
    {
        return decorated.toString();
    }
}
