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
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
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
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedResponseDecorator;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.api.LdapMessageContainer;
import org.apache.directory.api.ldap.codec.api.MessageDecorator;
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

    /** The map of registered {@link org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory}'s by request OID */
    private Map<String, ExtendedOperationFactory<?, ?>> extendendOperationsFactories = new HashMap<String, ExtendedOperationFactory<?, ?>>();

    /** The LDAP {@link ProtocolCodecFactory} implementation used */
    private ProtocolCodecFactory protocolCodecFactory;

    /** The list of controls to load at startup */
    public static final String CONTROLS_LIST = "apacheds.controls";

    /** The list of extended operations to load at startup */
    public static final String EXTENDED_OPERATIONS_LIST = "apacheds.extendedOperations";

    /** The (old) list of default controls to load at startup */
    private static final String OLD_DEFAULT_CONTROLS_LIST = "default.controls";

    /** The (old) list of extra controls to load at startup */
    private static final String OLD_EXTRA_CONTROLS_LIST = "extra.controls";

    /** The (old) list of default extended operation requests to load at startup */
    private static final String OLD_DEFAULT_EXTENDED_OPERATION_REQUESTS_LIST = "default.extendedOperation.requests";

    /** The (old) list of default extended operation responses to load at startup */
    private static final String OLD_DEFAULT_EXTENDED_OPERATION_RESPONSES_LIST = "default.extendedOperation.responses";

    /** The (old) list of extra extended operations to load at startup */
    private static final String OLD_EXTRA_EXTENDED_OPERATION_LIST = "extra.extendedOperations";


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
        List<String> controlsList = new ArrayList<String>();

        // Loading controls list from command line properties if it exists
        String controlsString = System.getProperty( CONTROLS_LIST );

        if ( !Strings.isEmpty( controlsString ) )
        {
            for ( String control : controlsString.split( "," ) )
            {
                controlsList.add( control );
            }
        }
        else
        {
            // Loading old default controls list from command line properties if it exists
            String oldDefaultControlsString = System.getProperty( OLD_DEFAULT_CONTROLS_LIST );

            if ( !Strings.isEmpty( oldDefaultControlsString ) )
            {
                for ( String control : oldDefaultControlsString.split( "," ) )
                {
                    controlsList.add( control );
                }
            }

            // Loading old extra controls list from command line properties if it exists
            String oldExtraControlsString = System.getProperty( OLD_EXTRA_CONTROLS_LIST );

            if ( !Strings.isEmpty( oldExtraControlsString ) )
            {
                for ( String control : oldExtraControlsString.split( "," ) )
                {
                    controlsList.add( control );
                }
            }
        }

        // Adding all controls
        if ( controlsList.size() > 0 )
        {
            for ( String control : controlsList )
            {
                loadControl( control );
            }
        }
    }


    /**
     * Loads a control from its FQCN.
     *
     * @param control the control FQCN
     * @throws Exception
     */
    private void loadControl( String control ) throws Exception
    {
        Class<?>[] types = new Class<?>[]
            { LdapApiService.class };
        @SuppressWarnings("unchecked")
        Class<? extends ControlFactory<?, ?>> clazz = ( Class<? extends ControlFactory<?, ?>> ) Class
            .forName( control );
        Constructor<?> constructor = clazz.getConstructor( types );

        ControlFactory<?, ?> factory = ( ControlFactory<?, ?> ) constructor.newInstance( new Object[]
            { this } );
        controlFactories.put( factory.getOid(), factory );
        LOG.info( "Registered control factory: {}", factory.getOid() );
    }


    /**
     * Load the extended operations
     * 
     * @throws Exception
     */
    private void loadExtendedOperations() throws Exception
    {
        List<String> extendedOperationsList = new ArrayList<String>();

        // Loading extended operations from command line properties if it exists
        String defaultExtendedOperationsList = System.getProperty( EXTENDED_OPERATIONS_LIST );

        if ( !Strings.isEmpty( defaultExtendedOperationsList ) )
        {
            for ( String extendedOperation : defaultExtendedOperationsList.split( "," ) )
            {
                extendedOperationsList.add( extendedOperation );
            }
        }
        else
        {
            // Loading old default extended operations requests list from command line properties if it exists
            String oldExtendedOperationsRequestsString = System
                .getProperty( OLD_DEFAULT_EXTENDED_OPERATION_REQUESTS_LIST );

            if ( !Strings.isEmpty( oldExtendedOperationsRequestsString ) )
            {
                for ( String extendedOperation : oldExtendedOperationsRequestsString.split( "," ) )
                {
                    extendedOperationsList.add( extendedOperation );
                }
            }

            // Loading old default extended operations requests list from command line properties if it exists
            String oldExtendedOperationsResponseString = System
                .getProperty( OLD_DEFAULT_EXTENDED_OPERATION_RESPONSES_LIST );

            if ( !Strings.isEmpty( oldExtendedOperationsResponseString ) )
            {
                for ( String extendedOperation : oldExtendedOperationsResponseString.split( "," ) )
                {
                    extendedOperationsList.add( extendedOperation );
                }
            }

            // Loading old extra extended operations list from command line properties if it exists
            String oldDefaultControlsString = System.getProperty( OLD_EXTRA_EXTENDED_OPERATION_LIST );

            if ( !Strings.isEmpty( oldDefaultControlsString ) )
            {
                for ( String extendedOperation : oldDefaultControlsString.split( "," ) )
                {
                    extendedOperationsList.add( extendedOperation );
                }
            }
        }

        // Adding all extended operations
        if ( extendedOperationsList.size() > 0 )
        {
            for ( String extendedOperation : extendedOperationsList )
            {
                loadExtendedOperation( extendedOperation );
            }
        }
    }


    private void loadExtendedOperation( String extendedOperation ) throws Exception
    {
        Class<?>[] types = new Class<?>[]
            { LdapApiService.class };
        @SuppressWarnings("unchecked")
        Class<? extends ExtendedOperationFactory<?, ?>> clazz = ( Class<? extends ExtendedOperationFactory<?, ?>> ) Class
            .forName( extendedOperation );
        Constructor<?> constructor = clazz.getConstructor( types );

        @SuppressWarnings("unchecked")
        ExtendedOperationFactory<ExtendedRequest<ExtendedResponse>, ExtendedResponse> factory = ( ExtendedOperationFactory<ExtendedRequest<ExtendedResponse>, ExtendedResponse> ) constructor
            .newInstance( new Object[]
                { this } );
        extendendOperationsFactories.put( factory.getOid(), factory );
        LOG.info( "Registered pre-bundled extended operation factory: {}", factory.getOid() );
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
        return Collections.unmodifiableSet( extendendOperationsFactories.keySet() ).iterator();
    }


    /**
     * {@inheritDoc}
     */
    public ExtendedOperationFactory<?, ?>
        registerExtendedRequest( ExtendedOperationFactory<?, ?> factory )
    {
        return extendendOperationsFactories.put( factory.getOid(), factory );
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
    public ExtendedOperationFactory<?, ?> unregisterExtendedRequest(
        String oid )
    {
        return extendendOperationsFactories.remove( oid );
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
            ExtendedOperationFactory<?, ?> extendedRequestFactory = extendendOperationsFactories.get( modelRequest
                .getRequestName() );
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
                ExtendedOperationFactory<?, ?> factory = extendendOperationsFactories.get( modelRequest
                    .getRequestName() );

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

        ExtendedOperationFactory<?, ?> extendedRequestFactory = extendendOperationsFactories.get( responseName );

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

        ExtendedOperationFactory<?, ?> extendedRequestFactory = extendendOperationsFactories
            .get( oid );

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

        ExtendedOperationFactory<?, ?> extendedRequestFactory = extendendOperationsFactories.get( decoratedMessage
            .getRequestName() );

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

        ExtendedOperationFactory<?, ?> extendedRequestFactory = extendendOperationsFactories.get( decoratedMessage
            .getResponseName() );

        if ( extendedRequestFactory != null )
        {
            resp = extendedRequestFactory.decorate( decoratedMessage );
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
        return extendendOperationsFactories.containsKey( oid );
    }
}
