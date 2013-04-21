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
package org.apache.directory.api.ldap.codec.standalone;


import java.lang.reflect.Constructor;
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
import org.apache.directory.api.ldap.codec.BasicControlDecorator;
import org.apache.directory.api.ldap.codec.api.CodecControl;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedRequestDecorator;
import org.apache.directory.api.ldap.codec.api.ExtendedRequestFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedResponseDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.api.MessageDecorator;
import org.apache.directory.api.ldap.codec.api.UnsolicitedResponseFactory;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.ExtendedRequest;
import org.apache.directory.api.ldap.model.message.ExtendedRequestImpl;
import org.apache.directory.api.ldap.model.message.ExtendedResponse;
import org.apache.directory.api.ldap.model.message.ExtendedResponseImpl;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.controls.OpaqueControl;
import org.apache.directory.api.util.Strings;
import org.apache.directory.api.util.exception.NotImplementedException;
import org.apache.mina.filter.codec.ProtocolCodecFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The default {@link org.apache.directory.api.ldap.codec.api.LdapApiService} implementation.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class StandaloneLdapApiService implements LdapApiService
{
    /** A logger */
    private static final Logger LOG = LoggerFactory.getLogger( StandaloneLdapApiService.class );

    /** The map of registered {@link org.apache.directory.api.ldap.codec.api.ControlFactory}'s */
    private Map<String, ControlFactory<?, ?>> controlFactories = new HashMap<String, ControlFactory<?, ?>>();

    /** The map of registered {@link org.apache.directory.api.ldap.codec.api.ExtendedRequestFactory}'s by request OID */
    private Map<String, ExtendedRequestFactory<?, ?>> extReqFactories = new HashMap<String, ExtendedRequestFactory<?, ?>>();

    /** The map of registered {@link UnsolicitedResponseFactory}'s by request OID */
    private Map<String, UnsolicitedResponseFactory<?>> unsolicitedFactories = new HashMap<String, UnsolicitedResponseFactory<?>>();

    /** The LDAP {@link ProtocolCodecFactory} implementation used */
    private ProtocolCodecFactory protocolCodecFactory;

    /** The list of default controls to load at startup */
    public static final String DEFAULT_CONTROLS_LIST = "default.controls";

    /** The list of extra controls to load at startup */
    public static final String EXTRA_CONTROLS_LIST = "extra.controls";

    /** The list of default extended operation requests to load at startup */
    public static final String DEFAULT_EXTENDED_OPERATION_REQUESTS_LIST = "default.extendedOperation.requests";

    /** The list of default extended operation responses to load at startup */
    public static final String DEFAULT_EXTENDED_OPERATION_RESPONSES_LIST = "default.extendedOperation.responses";

    /** The list of extra controls to load at startup */
    public static final String EXTRA_EXTENDED_OPERATION_LIST = "extra.extendedOperations";


    /**
     * Creates a new instance of StandaloneLdapCodecService. Optionally checks for
     * system property {@link #PLUGIN_DIRECTORY_PROPERTY}. Intended for use by 
     * unit test running tools like Maven's surefire:
     * <pre>
     *   &lt;properties&gt;
     *     &lt;codec.plugin.directory&gt;${project.build.directory}/pluginDirectory&lt;/codec.plugin.directory&gt;
     *   &lt;/properties&gt;
     * 
     *   &lt;build&gt;
     *     &lt;plugins&gt;
     *       &lt;plugin&gt;
     *         &lt;artifactId&gt;maven-surefire-plugin&lt;/artifactId&gt;
     *         &lt;groupId&gt;org.apache.maven.plugins&lt;/groupId&gt;
     *         &lt;configuration&gt;
     *           &lt;systemPropertyVariables&gt;
     *             &lt;workingDirectory&gt;${basedir}/target&lt;/workingDirectory&gt;
     *             &lt;felix.cache.rootdir&gt;
     *               ${project.build.directory}
     *             &lt;/felix.cache.rootdir&gt;
     *             &lt;felix.cache.locking&gt;
     *               true
     *             &lt;/felix.cache.locking&gt;
     *             &lt;org.osgi.framework.storage.clean&gt;
     *               onFirstInit
     *             &lt;/org.osgi.framework.storage.clean&gt;
     *             &lt;org.osgi.framework.storage&gt;
     *               osgi-cache
     *             &lt;/org.osgi.framework.storage&gt;
     *             &lt;codec.plugin.directory&gt;
     *               ${codec.plugin.directory}
     *             &lt;/codec.plugin.directory&gt;
     *           &lt;/systemPropertyVariables&gt;
     *         &lt;/configuration&gt;
     *       &lt;/plugin&gt;
     *       
     *       &lt;plugin&gt;
     *         &lt;groupId&gt;org.apache.maven.plugins&lt;/groupId&gt;
     *         &lt;artifactId&gt;maven-dependency-plugin&lt;/artifactId&gt;
     *         &lt;executions&gt;
     *           &lt;execution&gt;
     *             &lt;id&gt;copy&lt;/id&gt;
     *             &lt;phase&gt;compile&lt;/phase&gt;
     *             &lt;goals&gt;
     *               &lt;goal&gt;copy&lt;/goal&gt;
     *             &lt;/goals&gt;
     *             &lt;configuration&gt;
     *               &lt;artifactItems&gt;
     *                 &lt;artifactItem&gt;
     *                   &lt;groupId&gt;${project.groupId}&lt;/groupId&gt;
     *                   &lt;artifactId&gt;api-ldap-extras-codec&lt;/artifactId&gt;
     *                   &lt;version&gt;${project.version}&lt;/version&gt;
     *                   &lt;outputDirectory&gt;${codec.plugin.directory}&lt;/outputDirectory&gt;
     *                 &lt;/artifactItem&gt;
     *               &lt;/artifactItems&gt;
     *             &lt;/configuration&gt;
     *           &lt;/execution&gt;
     *         &lt;/executions&gt;
     *       &lt;/plugin&gt;
     *     &lt;/plugins&gt;
     *   &lt;/build&gt;
     * </pre>
     */
    public StandaloneLdapApiService() throws Exception
    {
        // Load the controls
        loadControls();

        // Load the extended operations
        loadExtendedOperations();

        // Load the schema elements
        //loadSchemaElements();

        // Load the network layer
        //loadNetworkLayer()

        if ( protocolCodecFactory == null )
        {
            try
            {
                @SuppressWarnings("unchecked")
                Class<? extends ProtocolCodecFactory> clazz = ( Class<? extends ProtocolCodecFactory> )
                    Class.forName( DEFAULT_PROTOCOL_CODEC_FACTORY );
                protocolCodecFactory = clazz.newInstance();
            }
            catch ( Exception cause )
            {
                throw new RuntimeException( "Failed to load default codec factory.", cause );
            }
        }
    }


    /**
     * Load the controls
     * 
     * @throws Exception
     */
    private void loadControls() throws Exception
    {
        // first load the default controls
        loadDefaultControls();

        // The load the extra controls
        loadExtraControls();
    }


    /**
     * Loads the Controls implemented out of the box in the codec.
     */
    private void loadDefaultControls() throws Exception
    {
        // Load defaults from command line properties if it exists
        String defaultControlsList = System.getProperty( DEFAULT_CONTROLS_LIST );

        if ( Strings.isEmpty( defaultControlsList ) )
        {
            return;
        }

        for ( String control : defaultControlsList.split( "," ) )
        {
            Class<?>[] types = new Class<?>[]
                { LdapApiService.class };
            Class<? extends ControlFactory<?, ?>> clazz = ( Class<? extends ControlFactory<?, ?>> ) Class
                .forName( control );
            Constructor<?> constructor = clazz.getConstructor( types );

            ControlFactory<?, ?> factory = ( ControlFactory<?, ?> ) constructor.newInstance( new Object[]
                { this } );
            controlFactories.put( factory.getOid(), factory );
            LOG.info( "Registered pre-bundled control factory: {}", factory.getOid() );
        }
    }


    /**
     * Loads the extra Controls
     */
    private void loadExtraControls() throws Exception
    {
        // Load extra from command line properties if it exists
        String extraControlsList = System.getProperty( EXTRA_CONTROLS_LIST );

        if ( Strings.isEmpty( extraControlsList ) )
        {
            return;
        }

        for ( String control : extraControlsList.split( "," ) )
        {
            Class<?>[] types = new Class<?>[]
                { LdapApiService.class };
            Class<? extends ControlFactory<?, ?>> clazz = ( Class<? extends ControlFactory<?, ?>> ) Class
                .forName( control );
            Constructor<?> constructor = clazz.getConstructor( types );

            ControlFactory<?, ?> factory = ( ControlFactory<?, ?> ) constructor.newInstance( new Object[]
                { this } );
            controlFactories.put( factory.getOid(), factory );
            LOG.info( "Registered pre-bundled control factory: {}", factory.getOid() );
        }
    }


    /**
     * Load the extended operations
     * 
     * @throws Exception
     */
    private void loadExtendedOperations() throws Exception
    {
        loadDefaultExtendedOperationRequests();
        loadDefaultExtendedOperationResponses();
        loadExtraExtendedOperations();
    }


    /**
     * Loads the default extended operation requests
     */
    private void loadDefaultExtendedOperationRequests() throws Exception
    {
        // Load from command line properties if it exists
        String defaultExtendedOperationsList = System.getProperty( DEFAULT_EXTENDED_OPERATION_REQUESTS_LIST );

        if ( Strings.isEmpty( defaultExtendedOperationsList ) )
        {
            return;
        }

        for ( String extendedOperation : defaultExtendedOperationsList.split( "," ) )
        {
            Class<?>[] types = new Class<?>[]
                { LdapApiService.class };
            Class<? extends ExtendedRequestFactory<?, ?>> clazz = ( Class<? extends ExtendedRequestFactory<?, ?>> ) Class
                .forName( extendedOperation );
            Constructor<?> constructor = clazz.getConstructor( types );

            ExtendedRequestFactory<?, ?> factory = ( ExtendedRequestFactory<?, ?> ) constructor
                .newInstance( new Object[]
                    { this } );
            extReqFactories.put( factory.getOid(), factory );
            LOG.info( "Registered pre-bundled extended operation factory: {}", factory.getOid() );
        }
    }


    /**
     * Loads the default extended operation responses
     */
    private void loadDefaultExtendedOperationResponses() throws Exception
    {
        // Load from command line properties if it exists
        String defaultExtendedOperationsList = System.getProperty( DEFAULT_EXTENDED_OPERATION_RESPONSES_LIST );

        if ( Strings.isEmpty( defaultExtendedOperationsList ) )
        {
            return;
        }

        for ( String extendedOperation : defaultExtendedOperationsList.split( "," ) )
        {
            Class<?>[] types = new Class<?>[]
                { LdapApiService.class };
            Class<? extends UnsolicitedResponseFactory<?>> clazz = ( Class<? extends UnsolicitedResponseFactory<?>> ) Class
                .forName( extendedOperation );
            Constructor<?> constructor = clazz.getConstructor( types );

            UnsolicitedResponseFactory<?> factory = ( UnsolicitedResponseFactory<?> ) constructor
                .newInstance( new Object[]
                    { this } );
            unsolicitedFactories.put( factory.getOid(), factory );
            LOG.info( "Registered pre-bundled extended operation factory: {}", factory.getOid() );
        }
    }


    /**
     * Loads the extra extended operations
     */
    private void loadExtraExtendedOperations()
    {

    }


    //-------------------------------------------------------------------------
    // LdapCodecService implementation methods
    //-------------------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    public ControlFactory<?, ?> registerControl( ControlFactory<?, ?> factory )
    {
        return controlFactories.put( factory.getOid(), factory );
    }


    /**
     * {@inheritDoc}
     */
    public ControlFactory<?, ?> unregisterControl( String oid )
    {
        return controlFactories.remove( oid );
    }


    /**
     * {@inheritDoc}
     */
    public Iterator<String> registeredControls()
    {
        return Collections.unmodifiableSet( controlFactories.keySet() ).iterator();
    }


    /**
     * {@inheritDoc}
     */
    public boolean isControlRegistered( String oid )
    {
        return controlFactories.containsKey( oid );
    }


    /**
     * {@inheritDoc}
     */
    public Iterator<String> registeredExtendedRequests()
    {
        return Collections.unmodifiableSet( extReqFactories.keySet() ).iterator();
    }


    /**
     * {@inheritDoc}
     */
    public ExtendedRequestFactory<?, ?> registerExtendedRequest( ExtendedRequestFactory<?, ?> factory )
    {
        return extReqFactories.put( factory.getOid(), factory );
    }


    /**
     * {@inheritDoc}
     */
    public ProtocolCodecFactory getProtocolCodecFactory()
    {
        return protocolCodecFactory;
    }


    /**
     * {@inheritDoc}
     */
    public ProtocolCodecFactory registerProtocolCodecFactory( ProtocolCodecFactory protocolCodecFactory )
    {
        ProtocolCodecFactory old = this.protocolCodecFactory;
        this.protocolCodecFactory = protocolCodecFactory;
        return old;
    }


    /**
     * {@inheritDoc}
     */
    public CodecControl<? extends Control> newControl( String oid )
    {
        ControlFactory<?, ?> factory = controlFactories.get( oid );

        if ( factory == null )
        {
            return new BasicControlDecorator<Control>( this, new OpaqueControl( oid ) );
        }

        return factory.newCodecControl();
    }


    /**
     * {@inheritDoc}
     */
    @SuppressWarnings("unchecked")
    public CodecControl<? extends Control> newControl( Control control )
    {
        if ( control == null )
        {
            throw new NullPointerException( "Control argument was null." );
        }

        // protect agains being multiply decorated
        if ( control instanceof CodecControl )
        {
            return ( org.apache.directory.api.ldap.codec.api.CodecControl<?> ) control;
        }

        @SuppressWarnings("rawtypes")
        ControlFactory factory = controlFactories.get( control.getOid() );

        if ( factory == null )
        {
            return new BasicControlDecorator<Control>( this, control );
        }

        return factory.newCodecControl( control );
    }


    /**
     * {@inheritDoc}
     */
    public javax.naming.ldap.Control toJndiControl( Control control ) throws EncoderException
    {
        CodecControl<? extends Control> decorator = newControl( control );
        ByteBuffer bb = ByteBuffer.allocate( decorator.computeLength() );
        decorator.encode( bb );
        bb.flip();
        BasicControl jndiControl =
            new BasicControl( control.getOid(), control.isCritical(), bb.array() );
        return jndiControl;
    }


    /**
     * {@inheritDoc}
     */
    public Control fromJndiControl( javax.naming.ldap.Control control ) throws DecoderException
    {
        @SuppressWarnings("rawtypes")
        ControlFactory factory = controlFactories.get( control.getID() );

        if ( factory == null )
        {
            OpaqueControl ourControl = new OpaqueControl( control.getID() );
            ourControl.setCritical( control.isCritical() );
            BasicControlDecorator<Control> decorator =
                new BasicControlDecorator<Control>( this, ourControl );
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
    public Asn1Container newMessageContainer()
    {
        return new LdapMessageContainer<MessageDecorator<? extends Message>>( this );
    }


    /**
     * {@inheritDoc}
     */
    public Iterator<String> registeredUnsolicitedResponses()
    {
        return Collections.unmodifiableSet( unsolicitedFactories.keySet() ).iterator();
    }


    /**
     * {@inheritDoc}
     */
    public UnsolicitedResponseFactory<?> registerUnsolicitedResponse( UnsolicitedResponseFactory<?> factory )
    {
        return unsolicitedFactories.put( factory.getOid(), factory );
    }


    /**
     * {@inheritDoc}
     */
    public javax.naming.ldap.ExtendedResponse toJndi( final ExtendedResponse modelResponse ) throws EncoderException
    {
        throw new NotImplementedException( "Figure out how to transform" );
    }


    /**
     * {@inheritDoc}
     */
    public ExtendedResponse fromJndi( javax.naming.ldap.ExtendedResponse jndiResponse ) throws DecoderException
    {
        throw new NotImplementedException( "Figure out how to transform" );
    }


    /**
     * {@inheritDoc}
     */
    public ExtendedRequestFactory<?, ?> unregisterExtendedRequest( String oid )
    {
        return extReqFactories.remove( oid );
    }


    /**
     * {@inheritDoc}
     */
    public UnsolicitedResponseFactory<?> unregisterUnsolicitedResponse( String oid )
    {
        return unsolicitedFactories.remove( oid );
    }


    /**
     * {@inheritDoc}
     */
    public ExtendedRequest<?> fromJndi( javax.naming.ldap.ExtendedRequest jndiRequest ) throws DecoderException
    {
        ExtendedRequestDecorator<?, ?> decorator =
            ( ExtendedRequestDecorator<?, ?> ) newExtendedRequest( jndiRequest.getID(), jndiRequest.getEncodedValue() );
        return decorator;
    }


    /**
     * {@inheritDoc}
     */
    public javax.naming.ldap.ExtendedRequest toJndi( final ExtendedRequest<?> modelRequest ) throws EncoderException
    {
        final String oid = modelRequest.getRequestName();
        final byte[] value;

        if ( modelRequest instanceof ExtendedRequestDecorator )
        {
            ExtendedRequestDecorator<?, ?> decorator = ( ExtendedRequestDecorator<?, ?> ) modelRequest;
            value = decorator.getRequestValue();
        }
        else
        {
            // have to ask the factory to decorate for us - can't do it ourselves
            ExtendedRequestFactory<?, ?> extendedRequestFactory = extReqFactories.get( modelRequest.getRequestName() );
            ExtendedRequestDecorator<?, ?> decorator = extendedRequestFactory.decorate( modelRequest );
            value = decorator.getRequestValue();
        }

        javax.naming.ldap.ExtendedRequest jndiRequest = new javax.naming.ldap.ExtendedRequest()
        {
            private static final long serialVersionUID = -4160980385909987475L;


            public String getID()
            {
                return oid;
            }


            public byte[] getEncodedValue()
            {
                return value;
            }


            public javax.naming.ldap.ExtendedResponse createExtendedResponse( String id, byte[] berValue, int offset,
                int length ) throws NamingException
            {
                ExtendedRequestFactory<?, ?> factory = extReqFactories.get( modelRequest.getRequestName() );

                try
                {
                    final ExtendedResponseDecorator<?> resp = ( ExtendedResponseDecorator<?> ) factory
                        .newResponse( berValue );
                    javax.naming.ldap.ExtendedResponse jndiResponse = new javax.naming.ldap.ExtendedResponse()
                    {
                        private static final long serialVersionUID = -7686354122066100703L;


                        public String getID()
                        {
                            return oid;
                        }


                        public byte[] getEncodedValue()
                        {
                            return resp.getResponseValue();
                        }
                    };

                    return jndiResponse;
                }
                catch ( DecoderException e )
                {
                    NamingException ne = new NamingException( "Unable to decode encoded response value: " +
                        Strings.dumpBytes( berValue ) );
                    ne.setRootCause( e );
                    throw ne;
                }
            }
        };

        return jndiRequest;
    }


    /**
     * {@inheritDoc}
     * @throws DecoderException 
     */
    @SuppressWarnings("unchecked")
    public <E extends ExtendedResponse> E newExtendedResponse( String responseName, int messageId,
        byte[] serializedResponse )
        throws DecoderException
    {
        ExtendedResponseDecorator<ExtendedResponse> resp;

        ExtendedRequestFactory<?, ?> extendedRequestFactory = extReqFactories.get( responseName );

        if ( extendedRequestFactory != null )
        {
            resp = ( ExtendedResponseDecorator<ExtendedResponse> ) extendedRequestFactory
                .newResponse( serializedResponse );
        }
        else
        {
            resp = new ExtendedResponseDecorator<ExtendedResponse>( this,
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
    public ExtendedRequest<?> newExtendedRequest( String oid, byte[] value )
    {
        ExtendedRequest<?> req = null;

        ExtendedRequestFactory<?, ?> extendedRequestFactory = extReqFactories.get( oid );

        if ( extendedRequestFactory != null )
        {
            if ( value == null )
            {
                req = extendedRequestFactory.newRequest();
            }
            else
            {
                req = extendedRequestFactory.newRequest( value );
            }
        }
        else
        {
            ExtendedRequestDecorator<ExtendedRequest<ExtendedResponse>, ExtendedResponse> decorator =
                new ExtendedRequestDecorator<ExtendedRequest<ExtendedResponse>, ExtendedResponse>( this,
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
    public ExtendedRequestDecorator<?, ?> decorate( ExtendedRequest<?> decoratedMessage )
    {
        ExtendedRequestDecorator<?, ?> req = null;

        ExtendedRequestFactory<?, ?> extendedRequestFactory = extReqFactories.get( decoratedMessage.getRequestName() );

        if ( extendedRequestFactory != null )
        {
            req = extendedRequestFactory.decorate( decoratedMessage );
        }
        else
        {
            req = new ExtendedRequestDecorator<ExtendedRequest<ExtendedResponse>, ExtendedResponse>( this,
                ( ExtendedRequest<ExtendedResponse> ) decoratedMessage );
        }

        return req;
    }


    /**
     * {@inheritDoc}
     */
    public ExtendedResponseDecorator<?> decorate( ExtendedResponse decoratedMessage )
    {
        ExtendedResponseDecorator<?> resp = null;

        UnsolicitedResponseFactory<?> unsolicitedResponseFactory = unsolicitedFactories.get( decoratedMessage
            .getResponseName() );
        ExtendedRequestFactory<?, ?> extendedRequestFactory = extReqFactories.get( decoratedMessage.getResponseName() );

        if ( extendedRequestFactory != null )
        {
            resp = extendedRequestFactory.decorate( decoratedMessage );
        }
        else if ( unsolicitedResponseFactory != null )
        {
            resp = unsolicitedResponseFactory.decorate( decoratedMessage );
        }
        else
        {
            resp = new ExtendedResponseDecorator<ExtendedResponse>( this, decoratedMessage );
        }

        return resp;
    }


    /**
     * {@inheritDoc}
     */
    public boolean isExtendedOperationRegistered( String oid )
    {
        return extReqFactories.containsKey( oid ) || unsolicitedFactories.containsKey( oid );
    }
}
