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
package org.apache.directory.api.ldap.codec.osgi;


import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.naming.NamingException;
import javax.naming.ldap.BasicControl;

import org.apache.directory.api.asn1.DecoderException;
import org.apache.directory.api.asn1.EncoderException;
import org.apache.directory.api.asn1.ber.Asn1Container;
import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.BasicControlDecorator;
import org.apache.directory.api.ldap.codec.api.AbstractMessageDecorator;
import org.apache.directory.api.ldap.codec.api.CodecControl;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.IntermediateResponseFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.controls.cascade.CascadeFactory;
import org.apache.directory.api.ldap.codec.controls.manageDsaIT.ManageDsaITFactory;
import org.apache.directory.api.ldap.codec.controls.proxiedauthz.ProxiedAuthzFactory;
import org.apache.directory.api.ldap.codec.controls.search.entryChange.EntryChangeFactory;
import org.apache.directory.api.ldap.codec.controls.search.pagedSearch.PagedResultsFactory;
import org.apache.directory.api.ldap.codec.controls.search.persistentSearch.PersistentSearchFactory;
import org.apache.directory.api.ldap.codec.controls.search.subentries.SubentriesFactory;
import org.apache.directory.api.ldap.codec.controls.sort.SortRequestFactory;
import org.apache.directory.api.ldap.codec.controls.sort.SortResponseFactory;
import org.apache.directory.api.ldap.codec.decorators.ExtendedRequestDecorator;
import org.apache.directory.api.ldap.codec.decorators.ExtendedResponseDecorator;
import org.apache.directory.api.ldap.codec.decorators.IntermediateResponseDecorator;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedRequestImpl;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.message.ExtendedResponseImpl;
import org.apache.directory.api.ldap.model.message.IntermediateResponse;
import org.apache.directory.api.ldap.model.message.IntermediateResponseImpl;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.controls.Cascade;
import org.apache.directory.api.ldap.model.message.controls.EntryChange;
import org.apache.directory.api.ldap.model.message.controls.ManageDsaIT;
import org.apache.directory.api.ldap.model.message.controls.OpaqueControl;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.ldap.model.message.controls.PersistentSearch;
import org.apache.directory.api.ldap.model.message.controls.ProxiedAuthz;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;
import org.apache.directory.api.ldap.model.message.controls.SortResponse;
import org.apache.directory.api.ldap.model.message.controls.Subentries;
import org.apache.directory.api.util.Strings;
import org.apache.directory.api.util.exception.NotImplementedException;
import org.apache.mina.filter.codec.ProtocolCodecFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The default {@link LdapApiService} implementation.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class DefaultLdapCodecService implements LdapApiService
{
    /** A logger */
    private static final Logger LOG = LoggerFactory.getLogger( DefaultLdapCodecService.class );

    /** The map of registered request {@link ControlFactory}'s */
    private Map<String, ControlFactory<? extends Control>> requestControlFactories = new HashMap<>();

    /** The map of registered response {@link ControlFactory}'s */
    private Map<String, ControlFactory<? extends Control>> responseControlFactories = new HashMap<>();

    /** The map of registered {@link org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory}'s by request OID */
    private Map<String, ExtendedOperationFactory> extendedOperationFactories = new HashMap<>();

    /** The map of registered {@link org.apache.directory.api.ldap.codec.api.IntermediateResponseFactory}'s by request OID */
    private Map<String, IntermediateResponseFactory> intermediateResponseFactories = new HashMap<>();

    /** The registered ProtocolCodecFactory */
    private ProtocolCodecFactory protocolCodecFactory;


    /**
     * Creates a new instance of DefaultLdapCodecService.
     */
    public DefaultLdapCodecService()
    {
        loadStockControls();
    }


    /**
     * Loads the Controls implement out of the box in the codec.
     */
    private void loadStockControls()
    {
        ControlFactory<Cascade> cascadeFactory = new CascadeFactory( this );
        requestControlFactories.put( cascadeFactory.getOid(), cascadeFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, cascadeFactory.getOid() ) );
        }

        ControlFactory<EntryChange> entryChangeFactory = new EntryChangeFactory( this );
        responseControlFactories.put( entryChangeFactory.getOid(), entryChangeFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, entryChangeFactory.getOid() ) );
        }

        ControlFactory<ManageDsaIT> manageDsaItFactory = new ManageDsaITFactory( this );
        requestControlFactories.put( manageDsaItFactory.getOid(), manageDsaItFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, manageDsaItFactory.getOid() ) );
        }

        ControlFactory<PagedResults> pageResultsFactory = new PagedResultsFactory( this );
        requestControlFactories.put( pageResultsFactory.getOid(), pageResultsFactory );
        responseControlFactories.put( pageResultsFactory.getOid(), pageResultsFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, pageResultsFactory.getOid() ) );
        }

        ControlFactory<PersistentSearch> persistentSearchFactory = new PersistentSearchFactory( this );
        requestControlFactories.put( persistentSearchFactory.getOid(), persistentSearchFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, persistentSearchFactory.getOid() ) );
        }

        ControlFactory<ProxiedAuthz> proxiedAuthzFactory = new ProxiedAuthzFactory( this );
        requestControlFactories.put( proxiedAuthzFactory.getOid(), proxiedAuthzFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, proxiedAuthzFactory.getOid() ) );
        }

        ControlFactory<SortRequest> sortRequestFactory = new SortRequestFactory( this );
        requestControlFactories.put( sortRequestFactory.getOid(), sortRequestFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, sortRequestFactory.getOid() ) );
        }

        ControlFactory<SortResponse> sortResponseFactory = new SortResponseFactory( this );
        responseControlFactories.put( sortResponseFactory.getOid(), sortResponseFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, sortResponseFactory.getOid() ) );
        }

        ControlFactory<Subentries> subentriesFactory = new SubentriesFactory( this );
        requestControlFactories.put( subentriesFactory.getOid(), subentriesFactory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06000_REGISTERED_CONTROL_FACTORY, subentriesFactory.getOid() ) );
        }
    }


    //-------------------------------------------------------------------------
    // LdapCodecService implementation methods
    //-------------------------------------------------------------------------

    /**
     * {@inheritDoc}
     */
    @Override
    public ControlFactory<?> registerRequestControl( ControlFactory<?> factory )
    {
        return requestControlFactories.put( factory.getOid(), factory );
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ControlFactory<?> registerResponseControl( ControlFactory<?> factory )
    {
        return responseControlFactories.put( factory.getOid(), factory );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ControlFactory<?> unregisterRequestControl( String oid )
    {
        return requestControlFactories.remove( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ControlFactory<?> unregisterResponseControl( String oid )
    {
        return responseControlFactories.remove( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<String> registeredRequestControls()
    {
        return Collections.unmodifiableSet( requestControlFactories.keySet() ).iterator();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<String> registeredResponseControls()
    {
        return Collections.unmodifiableSet( responseControlFactories.keySet() ).iterator();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isControlRegistered( String oid )
    {
        return requestControlFactories.containsKey( oid ) | responseControlFactories.containsKey( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<String> registeredExtendedRequests()
    {
        return Collections.unmodifiableSet( extendedOperationFactories.keySet() ).iterator();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedOperationFactory registerExtendedRequest( ExtendedOperationFactory factory )
    {
        return extendedOperationFactories.put( factory.getOid(), factory );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Iterator<String> registeredIntermediateResponses()
    {
        return Collections.unmodifiableSet( intermediateResponseFactories.keySet() ).iterator();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public IntermediateResponseFactory registerIntermediateResponse( IntermediateResponseFactory factory )
    {
        return intermediateResponseFactories.put( factory.getOid(), factory );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ProtocolCodecFactory getProtocolCodecFactory()
    {
        return protocolCodecFactory;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ProtocolCodecFactory registerProtocolCodecFactory( ProtocolCodecFactory protocolCodecFactory )
    {
        ProtocolCodecFactory oldFactory = this.protocolCodecFactory;
        this.protocolCodecFactory = protocolCodecFactory;
        return oldFactory;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CodecControl<? extends Control> newRequestControl( String oid )
    {
        ControlFactory<?> factory = requestControlFactories.get( oid );

        if ( factory == null )
        {
            return new BasicControlDecorator( this, new OpaqueControl( oid ) );
        }

        return factory.newCodecControl();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public CodecControl<? extends Control> newResponseControl( String oid )
    {
        ControlFactory<?> factory = responseControlFactories.get( oid );

        if ( factory == null )
        {
            return new BasicControlDecorator( this, new OpaqueControl( oid ) );
        }

        return factory.newCodecControl();
    }


    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("unchecked")
    @Override
    public CodecControl<? extends Control> newRequestControl( Control control )
    {
        if ( control == null )
        {
            throw new NullPointerException( I18n.err( I18n.ERR_05400_CONTROL_ARGUMENT_WAS_NULL ) );
        }

        // protect against being multiply decorated
        if ( control instanceof CodecControl )
        {
            return ( CodecControl<?> ) control;
        }

        @SuppressWarnings("rawtypes")
        ControlFactory factory = requestControlFactories.get( control.getOid() );

        if ( factory == null )
        {
            return new BasicControlDecorator( this, control );
        }

        return factory.newCodecControl( control );
    }


    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("unchecked")
    @Override
    public CodecControl<? extends Control> newResponseControl( Control control )
    {
        if ( control == null )
        {
            throw new NullPointerException( I18n.err( I18n.ERR_05400_CONTROL_ARGUMENT_WAS_NULL ) );
        }

        // protect against being multiply decorated
        if ( control instanceof CodecControl )
        {
            return ( CodecControl<?> ) control;
        }

        @SuppressWarnings("rawtypes")
        ControlFactory factory = responseControlFactories.get( control.getOid() );

        if ( factory == null )
        {
            return new BasicControlDecorator( this, control );
        }

        return factory.newCodecControl( control );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public javax.naming.ldap.Control toJndiControl( Control control ) throws EncoderException
    {
        CodecControl<? extends Control> decorator = newRequestControl( control );
        ByteBuffer bb = ByteBuffer.allocate( decorator.computeLength() );
        decorator.encode( bb );
        bb.flip();

        return new BasicControl( control.getOid(), control.isCritical(), bb.array() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Control fromJndiRequestControl( javax.naming.ldap.Control control ) throws DecoderException
    {
        @SuppressWarnings("rawtypes")
        ControlFactory factory = requestControlFactories.get( control.getID() );

        if ( factory == null )
        {
            OpaqueControl ourControl = new OpaqueControl( control.getID() );
            ourControl.setCritical( control.isCritical() );
            BasicControlDecorator decorator =
                new BasicControlDecorator( this, ourControl );
            decorator.setValue( control.getEncodedValue() );
            return decorator;
        }

        @SuppressWarnings("unchecked")
        CodecControl<? extends Control> ourControl = factory.newCodecControl();
        ourControl.setCritical( control.isCritical() );
        ourControl.setValue( control.getEncodedValue() );
        ourControl.decode( control.getEncodedValue() );

        return ourControl;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Control fromJndiResponseControl( javax.naming.ldap.Control control ) throws DecoderException
    {
        @SuppressWarnings("rawtypes")
        ControlFactory factory = responseControlFactories.get( control.getID() );

        if ( factory == null )
        {
            OpaqueControl ourControl = new OpaqueControl( control.getID() );
            ourControl.setCritical( control.isCritical() );
            BasicControlDecorator decorator =
                new BasicControlDecorator( this, ourControl );
            decorator.setValue( control.getEncodedValue() );
            return decorator;
        }

        @SuppressWarnings("unchecked")
        CodecControl<? extends Control> ourControl = factory.newCodecControl();
        ourControl.setCritical( control.isCritical() );
        ourControl.setValue( control.getEncodedValue() );
        ourControl.decode( control.getEncodedValue() );

        return ourControl;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Asn1Container newMessageContainer()
    {
        return new LdapMessageContainer<AbstractMessageDecorator<? extends Message>>( this );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedOperationFactory unregisterExtendedRequest( String oid )
    {
        return extendedOperationFactories.remove( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public IntermediateResponseFactory unregisterIntermediateResponse( String oid )
    {
        return intermediateResponseFactories.remove( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public javax.naming.ldap.ExtendedResponse toJndi( final ExtendedResponse modelResponse ) throws EncoderException
    {
        throw new NotImplementedException( I18n.err( I18n.ERR_05401_FIGURE_OUT_HOW_TO_TRANSFORM ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponse fromJndi( javax.naming.ldap.ExtendedResponse jndiResponse ) throws DecoderException
    {
        throw new NotImplementedException( I18n.err( I18n.ERR_05401_FIGURE_OUT_HOW_TO_TRANSFORM ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedRequest fromJndi( javax.naming.ldap.ExtendedRequest jndiRequest ) throws DecoderException
    {
        return newExtendedRequest( jndiRequest.getID(), jndiRequest.getEncodedValue() );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public javax.naming.ldap.ExtendedRequest toJndi( final ExtendedRequest modelRequest ) throws EncoderException
    {
        final String oid = modelRequest.getRequestName();
        final byte[] value;

        if ( modelRequest instanceof ExtendedRequestDecorator )
        {
            ExtendedRequestDecorator<?> decorator = ( ExtendedRequestDecorator<?> ) modelRequest;
            value = decorator.getRequestValue();
        }
        else
        {
            // have to ask the factory to decorate for us - can't do it ourselves
            ExtendedOperationFactory extendedRequestFactory = extendedOperationFactories.get( modelRequest
                .getRequestName() );
            ExtendedRequestDecorator<?> decorator = ( ExtendedRequestDecorator<?> ) extendedRequestFactory
                .decorate( modelRequest );
            value = decorator.getRequestValue();
        }

        return new javax.naming.ldap.ExtendedRequest()
        {
            private static final long serialVersionUID = -4160980385909987475L;


            @Override
            public String getID()
            {
                return oid;
            }


            @Override
            public byte[] getEncodedValue()
            {
                return value;
            }


            @Override
            public javax.naming.ldap.ExtendedResponse createExtendedResponse( String id, byte[] berValue, int offset,
                int length ) throws NamingException
            {
                ExtendedOperationFactory factory = extendedOperationFactories
                    .get( modelRequest.getRequestName() );

                try
                {
                    final ExtendedResponseDecorator<?> resp = ( ExtendedResponseDecorator<?> ) factory
                        .newResponse( berValue );
                    return new javax.naming.ldap.ExtendedResponse()
                    {
                        private static final long serialVersionUID = -7686354122066100703L;


                        @Override
                        public String getID()
                        {
                            return oid;
                        }


                        @Override
                        public byte[] getEncodedValue()
                        {
                            return resp.getResponseValue();
                        }
                    };
                }
                catch ( DecoderException de )
                {
                    NamingException ne = new NamingException( I18n.err( I18n.ERR_05402_UNABLE_TO_ENCODE_RESPONSE_VALUE,
                        Strings.dumpBytes( berValue ) ) );
                    ne.setRootCause( de );
                    throw ne;
                }
            }
        };
    }


    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("unchecked")
    @Override
    public <E extends ExtendedResponse> E newExtendedResponse( String responseName, int messageId,
        byte[] serializedResponse )
        throws DecoderException
    {
        ExtendedResponseDecorator<ExtendedResponse> resp;

        ExtendedOperationFactory extendedRequestFactory = extendedOperationFactories.get( responseName );

        if ( extendedRequestFactory != null )
        {
            resp = ( ExtendedResponseDecorator<ExtendedResponse> ) extendedRequestFactory
                .newResponse( serializedResponse );
        }
        else
        {
            resp = new ExtendedResponseDecorator( this,
                new ExtendedResponseImpl( responseName ) );
            resp.setResponseValue( serializedResponse );
            resp.setResponseName( responseName );
        }

        resp.setMessageId( messageId );

        return ( E ) resp;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedRequest newExtendedRequest( String oid, byte[] value )
    {
        ExtendedRequest req;

        ExtendedOperationFactory extendedRequestFactory = extendedOperationFactories.get( oid );

        if ( extendedRequestFactory != null )
        {
            req = extendedRequestFactory.newRequest( value );
        }
        else
        {
            ExtendedRequestDecorator<ExtendedRequest> decorator =
                new ExtendedRequestDecorator( this,
                    new ExtendedRequestImpl() );
            decorator.setRequestName( oid );
            decorator.setRequestValue( value );
            req = decorator;
        }

        return req;
    }


    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("unchecked")
    @Override
    public <I extends IntermediateResponse> I newIntermediateResponse( String responseName, int messageId,
        byte[] serializedResponse ) throws DecoderException
    {
        IntermediateResponseDecorator<IntermediateResponse> resp;

        IntermediateResponseFactory intermediateResponseFactory = intermediateResponseFactories.get( responseName );

        if ( intermediateResponseFactory != null )
        {
            resp = ( IntermediateResponseDecorator<IntermediateResponse> ) intermediateResponseFactory
                .newResponse( serializedResponse );
        }
        else
        {
            resp = new IntermediateResponseDecorator<IntermediateResponse>( this, new IntermediateResponseImpl( responseName ) );
            resp.setResponseValue( serializedResponse );
            resp.setResponseName( responseName );
        }

        resp.setMessageId( messageId );

        return ( I ) resp;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedRequestDecorator<?> decorate( ExtendedRequest decoratedMessage )
    {
        ExtendedOperationFactory extendedRequestFactory = extendedOperationFactories.get( decoratedMessage
            .getRequestName() );

        if ( extendedRequestFactory != null )
        {
            return ( ExtendedRequestDecorator<?> ) extendedRequestFactory.decorate( decoratedMessage );
        }
        else
        {
            return new ExtendedRequestDecorator<>( this, decoratedMessage );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public ExtendedResponseDecorator<?> decorate( ExtendedResponse decoratedMessage )
    {
        ExtendedOperationFactory extendedRequestFactory = extendedOperationFactories.get( decoratedMessage
            .getResponseName() );

        if ( extendedRequestFactory != null )
        {
            return ( ExtendedResponseDecorator<?> ) extendedRequestFactory.decorate( decoratedMessage );
        }
        else
        {
            return new ExtendedResponseDecorator<>( this, decoratedMessage );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public IntermediateResponseDecorator<?> decorate( IntermediateResponse decoratedMessage )
    {
        IntermediateResponseFactory intermediateResponseFactory = intermediateResponseFactories.get( decoratedMessage
            .getResponseName() );

        if ( intermediateResponseFactory != null )
        {
            return ( IntermediateResponseDecorator<?> ) intermediateResponseFactory.decorate( decoratedMessage );
        }
        else
        {
            return new IntermediateResponseDecorator<>( this, decoratedMessage );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isExtendedOperationRegistered( String oid )
    {
        return extendedOperationFactories.containsKey( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isIntermediateResponseRegistered( String oid )
    {
        return intermediateResponseFactories.containsKey( oid );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, ControlFactory<? extends Control>> getRequestControlFactories()
    {
        return requestControlFactories;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Map<String, ControlFactory<? extends Control>> getResponseControlFactories()
    {
        return responseControlFactories;
    }


    /**
     * @param requestControlFactories the request controlFactories to set
     */
    public void setRequestControlFactories( Map<String, ControlFactory<? extends Control>> requestControlFactories )
    {
        this.requestControlFactories = requestControlFactories;
    }


    /**
     * @param responseControlFactories the response controlFactories to set
     */
    public void setResponseControlFactories( Map<String, ControlFactory<? extends Control>> responseControlFactories )
    {
        this.responseControlFactories = responseControlFactories;
    }


    /**
     * @return the extendedOperationFactories
     */
    public Map<String, ExtendedOperationFactory> getExtendedOperationFactories()
    {
        return extendedOperationFactories;
    }


    /**
     * @return the intermediateResponseFactories
     */
    public Map<String, IntermediateResponseFactory> getIntermediateResponseFactories()
    {
        return intermediateResponseFactories;
    }


    /**
     * @param extendedOperationFactories the extendedOperationFactories to set
     */
    public void setExtendedOperationFactories( Map<String, ExtendedOperationFactory> extendedOperationFactories )
    {
        this.extendedOperationFactories = extendedOperationFactories;
    }


    /**
     * @param intermediateResponseFactories the intermediateResponseFactories to set
     */
    public void setIntermediateResponseFactories( Map<String, IntermediateResponseFactory> intermediateResponseFactories )
    {
        this.intermediateResponseFactories = intermediateResponseFactories;
    }


    /**
     * @param protocolCodecFactory the protocolCodecFactory to set
     */
    public void setProtocolCodecFactory( ProtocolCodecFactory protocolCodecFactory )
    {
        this.protocolCodecFactory = protocolCodecFactory;
    }
}
