/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.codec.StockCodecFactoryUtil;
import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.IntermediateOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.osgi.DefaultLdapCodecService;
import org.apache.directory.api.ldap.extras.ExtrasCodecFactoryUtil;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.util.Strings;
import org.apache.mina.filter.codec.ProtocolCodecFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The default {@link org.apache.directory.api.ldap.codec.api.LdapApiService} implementation.
 * It loads the Controls, ExtendedOperations and IntermediateResponses as defined in the following system parameters :
 * <ul>
 *   <li>Controls :
 *     <ul>
 *       <li>apacheds.request.controls</li>
 *       <li>apacheds.response.controls</li>
 *       <li>default.controls</li>
 *     </ul>
 *   </li>
 *   <li>ExtendedOperations :
 *     <ul>
 *       <li>apacheds.extendedOperations</li>
 *       <li>extra.extendedOperations</li>
 *     </ul>
 *   </li>
 *   <li>IntermediateResponses :
 *     <ul>
 *       <li>apacheds.intermediateResponses</li>
 *     </ul>
 *   </li>
 * </ul>
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class StandaloneLdapApiService extends DefaultLdapCodecService
{
    /** A logger */
    private static final Logger LOG = LoggerFactory.getLogger( StandaloneLdapApiService.class );

    /** The list of request controls to load at startup */
    public static final String REQUEST_CONTROLS_LIST = "apacheds.request.controls";

    /** The list of response controls to load at startup */
    public static final String RESPONSE_CONTROLS_LIST = "apacheds.response.controls";

    /** The list of extended operations to load at startup */
    public static final String EXTENDED_OPERATIONS_LIST = "apacheds.extendedOperations";

    /** The list of Intermediate responses to load at startup */
    public static final String INTERMEDIATE_RESPONSES_LIST = "apacheds.intermediateResponses";

    /** The (old) list of default controls to load at startup */
    private static final String OLD_DEFAULT_CONTROLS_LIST = "default.controls";

    /** The (old) list of extra extended operations to load at startup */
    private static final String OLD_EXTRA_EXTENDED_OPERATION_LIST = "extra.extendedOperations";
    
    /** The control's type */
    public enum ControlType
    {
        /** A Request control type */
        REQUEST( REQUEST_CONTROLS_LIST ),

        /** A Response control type */
        RESPONSE( RESPONSE_CONTROLS_LIST );
        
        private String property;
        
        ControlType( String property )
        {
            this.property = property;
        }
        
        private String getProperty()
        {
            return property;
        }
    }


    /**
     * Creates a new instance of StandaloneLdapCodecService.
     * <br><br>
     * The following pom configuration is intended for use by unit test running
     * tools like Maven's surefire:
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
     *
     * @throws Exception If we had an issue initializing the LDAP service
     */
    public StandaloneLdapApiService() throws Exception
    {
        this( getControlsFromSystemProperties( ControlType.REQUEST ), 
            getControlsFromSystemProperties( ControlType.RESPONSE ), 
            getExtendedOperationsFromSystemProperties(), 
            getIntermediateResponsesFromSystemProperties() );
    }


    /**
     * Creates a new instance of StandaloneLdapApiService.
     *
     * @param requestControls The list of request controls to store
     * @param responseControls The list of response controls to store
     * @param extendedOperations The list of extended operations to store
     * @param intermediateResponses The list of intermediate responsess to store
     * @throws Exception If we had an issue with one of the two lists
     */
    public StandaloneLdapApiService( List<String> requestControls, 
        List<String> responseControls, List<String> extendedOperations,
        List<String> intermediateResponses ) throws Exception
    {
        StockCodecFactoryUtil.loadStockControls( this );
        ExtrasCodecFactoryUtil.loadExtrasControls( this );
        ExtrasCodecFactoryUtil.loadExtrasExtendedOperations( this );
        ExtrasCodecFactoryUtil.loadExtrasIntermediateResponses( this );

        // Load the controls
        loadControls( requestControls, getRequestControlFactories() );
        loadControls( responseControls, getResponseControlFactories() );

        // Load the extended operations
        loadExtendedOperations( extendedOperations );

        // Load the extended operations
        loadIntermediateResponse( intermediateResponses );

        if ( getProtocolCodecFactory() == null )
        {
            try
            {
                @SuppressWarnings("unchecked")
                Class<? extends ProtocolCodecFactory> clazz = ( Class<? extends ProtocolCodecFactory> )
                    Class.forName( DEFAULT_PROTOCOL_CODEC_FACTORY );
                Constructor<? extends ProtocolCodecFactory> constructor =
                    clazz.getConstructor( LdapApiService.class );

                if ( constructor != null )
                {
                    setProtocolCodecFactory( constructor.newInstance( this ) );
                }
                else
                {
                    setProtocolCodecFactory( clazz.newInstance() );
                }
            }
            catch ( Exception cause )
            {
                throw new RuntimeException( I18n.err( I18n.ERR_06000_FAILED_TO_LOAD_DEFAULT_CODEC_FACTORY ), cause );
            }
        }
    }


    /**
     * Parses the system properties to obtain the controls list.
     *
     * @param type The control's type
     * @return A list of controls
     */
    private static List<String> getControlsFromSystemProperties( ControlType type )
    {
        List<String> controlsList = new ArrayList<>();

        if ( type == ControlType.REQUEST )
        {            
            // Loading request controls list from command line properties if it exists
            String controlsString = System.getProperty( type.getProperty() );
    
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
            }
        }

        return controlsList;
    }


    /**
     * Parses the system properties to obtain the extended operations.
     * Such extended operations are stored in the <b>apacheds.extendedOperations</b>
     * and <b>default.extendedOperation.requests</b> system properties.
     *
     * @return a list of extended operation
     */
    private static List<String> getExtendedOperationsFromSystemProperties()
    {
        List<String> extendedOperationsList = new ArrayList<>();

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
            // Loading old extra extended operations list from command line properties if it exists
            String oldDefaultExtendedOperationsString = System.getProperty( OLD_EXTRA_EXTENDED_OPERATION_LIST );

            if ( !Strings.isEmpty( oldDefaultExtendedOperationsString ) )
            {
                for ( String extendedOperation : oldDefaultExtendedOperationsString.split( "," ) )
                {
                    extendedOperationsList.add( extendedOperation );
                }
            }
        }

        return extendedOperationsList;
    }


    /**
     * Parses the system properties to obtain the intermediate responses.
     * Such intermediate responses are stored in the <b>apacheds.intermediateResponses</b>
     * and <b>default.intermediateResponses.requests</b> system properties.
     *
     * @return a list of intermediate responses
     */
    private static List<String> getIntermediateResponsesFromSystemProperties()
    {
        List<String> intermediateResponsesList = new ArrayList<>();

        // Loading extended operations from command line properties if it exists
        String defaultIntermediateResponsesList = System.getProperty( INTERMEDIATE_RESPONSES_LIST );

        if ( !Strings.isEmpty( defaultIntermediateResponsesList ) )
        {
            for ( String intermediateResponse : defaultIntermediateResponsesList.split( "," ) )
            {
                intermediateResponsesList.add( intermediateResponse );
            }
        }

        return intermediateResponsesList;
    }


    /**
     * Loads a list of controls from their FQCN.
     *
     * @param controlsList The list of controls to load
     * @param controlFactories The set of control factories already loaded
     * @throws Exception if a control could not be loaded
     */
    private void loadControls( List<String> controlsList, Map<String, ControlFactory<? extends Control>> controlFactories )
        throws Exception
    {
        // Adding all controls
        if ( !controlsList.isEmpty() )
        {
            for ( String controlFQCN : controlsList )
            {
                loadControl( controlFQCN, controlFactories );
            }
        }
    }


    /**
     * Loads a control from its FQCN.
     *
     * @param controlFQCN The control FQCN
     * @param controlFactories The set of control factories already loaded
     * @throws Exception If the control could not be loaded
     */
    private void loadControl( String controlFQCN, Map<String, ControlFactory<? extends Control>> controlFactories )
        throws Exception
    {
        if ( controlFactories.containsKey( controlFQCN ) )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_06003_CONTROL_FACTORY_ALREADY_LOADED, controlFQCN ) );
            }

            return;
        }

        Class<?>[] types = new Class<?>[]
            { LdapApiService.class };
        // note, trimming whitespace doesnt hurt as it is a class name and
        // helps DI containers that use xml config as xml ignores whitespace
        @SuppressWarnings("unchecked")
        Class<? extends ControlFactory<?>> clazz = ( Class<? extends ControlFactory<?>> ) Class
            .forName( controlFQCN.trim() );
        Constructor<?> constructor = clazz.getConstructor( types );

        ControlFactory<?> factory = ( ControlFactory<?> ) constructor.newInstance( this );
        controlFactories.put( factory.getOid(), factory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06004_REGISTERED_CONTROL_FACTORY, factory.getOid() ) );
        }
    }


    /**
     * Loads a list of extended operation from their FQCN
     *
     * @param extendedOperationsList The list of extended operations to load
     * @throws Exception If an extended operations cannot be loaded
     */
    private void loadExtendedOperations( List<String> extendedOperationsList ) throws Exception
    {
        // Adding all extended operations
        if ( !extendedOperationsList.isEmpty() )
        {
            for ( String extendedOperationFQCN : extendedOperationsList )
            {
                loadExtendedRequest( extendedOperationFQCN );
            }
        }
    }


    /**
     * Loads an extended request from its FQCN
     *
     * @param extendedRequestFQCN The extended operations to load
     * @throws Exception If the extended operations cannot be loaded
     */
    private void loadExtendedRequest( String extendedRequestFQCN ) throws Exception
    {
        if ( getExtendedRequestFactories().containsKey( extendedRequestFQCN ) )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_06005_EXTENDED_OP_FACTORY_ALREADY_LOADED, extendedRequestFQCN ) );
            }

            return;
        }

        Class<?>[] types = new Class<?>[]
            { LdapApiService.class };

        // note, trimming whitespace doesn't hurt as it is a class name and
        // helps DI containers that use xml config as xml ignores whitespace
        @SuppressWarnings("unchecked")
        Class<? extends ExtendedOperationFactory> clazz = ( Class<? extends ExtendedOperationFactory> ) Class
            .forName( extendedRequestFQCN.trim() );
        Constructor<?> constructor = clazz.getConstructor( types );

        ExtendedOperationFactory factory = ( ExtendedOperationFactory ) constructor
            .newInstance( this );
        getExtendedRequestFactories().put( factory.getOid(), factory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06001_REGISTERED_EXTENDED_OP_FACTORY, factory.getOid() ) );
        }
    }


    /**
     * Loads a list of intermediate responses from their FQCN
     *
     * @param intermediateResponsesList The list of intermediate response to load
     * @throws Exception If one of the intermediate response cannot be loaded
     */
    private void loadIntermediateResponse( List<String> intermediateResponsesList ) throws Exception
    {
        // Adding all extended operations
        if ( !intermediateResponsesList.isEmpty() )
        {
            for ( String intermediateResponseFQCN : intermediateResponsesList )
            {
                loadIntermediateResponse( intermediateResponseFQCN );
            }
        }
    }


    /**
     * Loads an intermediate responses from its FQCN
     *
     * @param intermediateResponseFQCN The intermediate response to load
     * @throws Exception If the intermediate response cannot be loaded
     */
    private void loadIntermediateResponse( String intermediateResponseFQCN ) throws Exception
    {
        if ( getIntermediateResponseFactories().containsKey( intermediateResponseFQCN ) )
        {
            if ( LOG.isDebugEnabled() )
            {
                LOG.debug( I18n.msg( I18n.MSG_06006_INTERMEDIATE_FACTORY_ALREADY_LOADED, intermediateResponseFQCN ) );
            }

            return;
        }

        Class<?>[] types = new Class<?>[]
            {};

        // note, trimming whitespace doesn't hurt as it is a class name and
        // helps DI containers that use xml config as xml ignores whitespace
        @SuppressWarnings("unchecked")
        Class<? extends IntermediateOperationFactory> clazz = ( Class<? extends IntermediateOperationFactory> ) Class
            .forName( intermediateResponseFQCN.trim() );
        Constructor<?> constructor = clazz.getConstructor( types );

        IntermediateOperationFactory factory = ( IntermediateOperationFactory ) constructor
            .newInstance();
        getIntermediateResponseFactories().put( factory.getOid(), factory );

        if ( LOG.isInfoEnabled() )
        {
            LOG.info( I18n.msg( I18n.MSG_06007_REGISTRED_INTERMEDIATE_RESP_FACTORY, factory.getOid() ) );
        }
    }
}
