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
package org.apache.directory.api.ldap.extras.extended.ads_impl.storedProcedure;


import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.List;

import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.tlv.BerValue;
import org.apache.directory.api.asn1.ber.tlv.TLV;
import org.apache.directory.api.asn1.ber.tlv.UniversalTag;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.api.ExtendedRequestDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.extras.extended.storedProcedure.StoredProcedureParameter;
import org.apache.directory.api.ldap.extras.extended.storedProcedure.StoredProcedureRequest;
import org.apache.directory.api.ldap.extras.extended.storedProcedure.StoredProcedureRequestImpl;
import org.apache.directory.api.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A Decorator for stored procedure extended operation requests.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class StoredProcedureRequestDecorator extends ExtendedRequestDecorator<StoredProcedureRequest>
    implements StoredProcedureRequest
{
    private static final Logger LOG = LoggerFactory.getLogger( StoredProcedureRequestDecorator.class );

    private StoredProcedureParameter currentParameter;

    /** The stored procedure length */
    private int storedProcedureLength;

    /** The parameters length */
    private int parametersLength;

    /** The list of all parameter lengths */
    private List<Integer> parameterLength;


    /**
     * Create a new StoredProcedureRequestDecorator instance 
     * @param codec The LDAP API service to use
     */
    public StoredProcedureRequestDecorator( LdapApiService codec )
    {
        super( codec, new StoredProcedureRequestImpl() );
    }


    /**
     * Create a new StoredProcedureRequestDecorator instance 
     * @param codec The LDAP API service to use
     * @param decoratedRequest The decorated request
     */
    public StoredProcedureRequestDecorator( LdapApiService codec, StoredProcedureRequest decoratedRequest )
    {
        super( codec, decoratedRequest );
        if ( decoratedRequest == null )
        {
            throw new NullPointerException( "decorated stored procedulre request is null" );
        }
    }


    /**
     * @return The current parameter
     */
    public StoredProcedureParameter getCurrentParameter()
    {
        return currentParameter;
    }


    /**
     * Sets the current parameter
     * 
     * @param currentParameter The current parameter
     */
    public void setCurrentParameter( StoredProcedureParameter currentParameter )
    {
        this.currentParameter = currentParameter;
    }


    /**
     * Compute the StoredProcedure length 
     * <pre>
     * 0x30 L1 
     *   | 
     *   +--&gt; 0x04 L2 language
     *   +--&gt; 0x04 L3 procedure
     *  [+--&gt; 0x30 L4 (parameters)
     *          |
     *          +--&gt; 0x30 L5-1 (parameter)
     *          |      |
     *          |      +--&gt; 0x04 L6-1 type
     *          |      +--&gt; 0x04 L7-1 value
     *          |      
     *          +--&gt; 0x30 L5-2 (parameter)
     *          |      |
     *          |      +--&gt; 0x04 L6-2 type
     *          |      +--&gt; 0x04 L7-2 value
     *          |
     *          +--&gt; ...
     *          |      
     *          +--&gt; 0x30 L5-m (parameter)
     *                 |
     *                 +--&gt; 0x04 L6-m type
     *                 +--&gt; 0x04 L7-m value
     * </pre>
     */
    /* no qualifier */ int computeLengthInternal()
    {
        // The language
        byte[] languageBytes = Strings.getBytesUtf8( getDecorated().getLanguage() );

        int languageLength = 1 + TLV.getNbBytes( languageBytes.length )
            + languageBytes.length;

        byte[] procedure = getDecorated().getProcedure();

        // The procedure
        int procedureLength = 1 + TLV.getNbBytes( procedure.length )
            + procedure.length;

        // Compute parameters length value
        if ( getDecorated().getParameters() != null )
        {
            parameterLength = new LinkedList<>();

            for ( StoredProcedureParameter spParam : getDecorated().getParameters() )
            {
                int localParameterLength;
                int localParamTypeLength;
                int localParamValueLength;

                localParamTypeLength = 1 + TLV.getNbBytes( spParam.getType().length ) + spParam.getType().length;
                localParamValueLength = 1 + TLV.getNbBytes( spParam.getValue().length ) + spParam.getValue().length;

                localParameterLength = localParamTypeLength + localParamValueLength;

                parametersLength += 1 + TLV.getNbBytes( localParameterLength ) + localParameterLength;

                parameterLength.add( localParameterLength );
            }
        }

        int localParametersLength = 1 + TLV.getNbBytes( parametersLength ) + parametersLength;
        storedProcedureLength = languageLength + procedureLength + localParametersLength;

        return 1 + TLV.getNbBytes( storedProcedureLength ) + storedProcedureLength;
    }


    /**
     * Encodes the StoredProcedure extended operation.
     * 
     * @return A ByteBuffer that contains the encoded PDU
     * @throws org.apache.directory.api.asn1.EncoderException If anything goes wrong.
     */
    /* no qualifier */ ByteBuffer encodeInternal() throws EncoderException
    {
        // Allocate the bytes buffer.
        ByteBuffer bb = ByteBuffer.allocate( computeLengthInternal() );

        try
        {
            // The StoredProcedure Tag
            bb.put( UniversalTag.SEQUENCE.getValue() );
            bb.put( TLV.getBytes( storedProcedureLength ) );

            // The language
            BerValue.encode( bb, getDecorated().getLanguage() );

            // The procedure
            BerValue.encode( bb, getDecorated().getProcedure() );

            // The parameters sequence
            bb.put( UniversalTag.SEQUENCE.getValue() );
            bb.put( TLV.getBytes( parametersLength ) );

            // The parameters list
            if ( ( getDecorated().getParameters() != null ) && ( !getDecorated().getParameters().isEmpty() ) )
            {
                int parameterNumber = 0;

                for ( StoredProcedureParameter spParam : getDecorated().getParameters() )
                {
                    // The parameter sequence
                    bb.put( UniversalTag.SEQUENCE.getValue() );
                    int localParameterLength = parameterLength.get( parameterNumber );
                    bb.put( TLV.getBytes( localParameterLength ) );

                    // The parameter type
                    BerValue.encode( bb, spParam.getType() );

                    // The parameter value
                    BerValue.encode( bb, spParam.getValue() );

                    // Go to the next parameter
                    parameterNumber++;
                }
            }
        }
        catch ( BufferOverflowException boe )
        {
            throw new EncoderException( I18n.err( I18n.ERR_04005 ), boe );
        }

        return bb;
    }


    /**
     * Returns the StoredProcedure string
     * 
     * @return The StoredProcedure string
     */
    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();

        sb.append( "    StoredProcedure\n" );
        sb.append( "        Language : '" ).append( getDecorated().getLanguage() ).append( "'\n" );
        sb.append( "        Procedure\n" ).append( getDecorated().getProcedureSpecification() ).append( "'\n" );

        if ( ( getDecorated().getParameters() == null ) || ( !getDecorated().getParameters().isEmpty() ) )
        {
            sb.append( "        No parameters\n" );
        }
        else
        {
            sb.append( "        Parameters\n" );

            int i = 1;

            for ( StoredProcedureParameter spParam : getDecorated().getParameters() )
            {
                sb.append( "            type[" ).append( i ).append( "] : '" ).
                    append( Strings.utf8ToString( spParam.getType() ) ).append( "'\n" );
                sb.append( "            value[" ).append( i ).append( "] : '" ).
                    append( Strings.dumpBytes( spParam.getValue() ) ).append( "'\n" );
            }
        }

        return sb.toString();
    }


    @Override
    public void setProcedure( byte[] procedure )
    {
        getDecorated().setProcedure( procedure );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setRequestValue( byte[] payload )
    {
        StoredProcedureDecoder decoder = new StoredProcedureDecoder();
        StoredProcedureContainer container = new StoredProcedureContainer();

        container.setStoredProcedure( this );

        try
        {
            decoder.decode( ByteBuffer.wrap( payload ), container );
        }
        catch ( Exception e )
        {
            LOG.error( I18n.err( I18n.ERR_04165 ), e );
            throw new RuntimeException( e );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getRequestValue()
    {
        if ( requestValue == null )
        {
            try
            {
                requestValue = encodeInternal().array();
            }
            catch ( EncoderException e )
            {
                LOG.error( I18n.err( I18n.ERR_04174 ), e );
                throw new RuntimeException( e );
            }
        }

        return requestValue;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getLanguage()
    {
        return getDecorated().getLanguage();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void setLanguage( String language )
    {
        getDecorated().setLanguage( language );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String getProcedureSpecification()
    {
        return getDecorated().getProcedureSpecification();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public int size()
    {
        return getDecorated().size();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Object getParameterType( int index )
    {
        return getDecorated().getParameterType( index );
    }


    /**
     * {@inheritDoc}
     */

    @Override
    public Class<?> getJavaParameterType( int index )
    {
        return getDecorated().getJavaParameterType( index );
    }


    /**
     * {@inheritDoc}
     */

    @Override
    public Object getParameterValue( int index )
    {
        return getDecorated().getParameterValue( index );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Object getJavaParameterValue( int index )
    {
        return getDecorated().getJavaParameterValue( index );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void addParameter( Object type, Object value )
    {
        getDecorated().addParameter( type, value );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public byte[] getProcedure()
    {
        return getDecorated().getProcedure();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public List<StoredProcedureParameter> getParameters()
    {
        return getDecorated().getParameters();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void addParameter( StoredProcedureParameter parameter )
    {
        getDecorated().addParameter( parameter );
    }
}
