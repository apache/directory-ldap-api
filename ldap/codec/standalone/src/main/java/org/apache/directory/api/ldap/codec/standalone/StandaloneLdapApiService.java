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
import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.ldap.codec.api.ControlFactory;
import org.apache.directory.api.ldap.codec.api.ExtendedOperationFactory;
import org.apache.directory.api.ldap.codec.api.LdapApiService;
import org.apache.directory.api.ldap.codec.osgi.DefaultLdapCodecService;
import org.apache.directory.api.util.Strings;
import org.apache.mina.filter.codec.ProtocolCodecFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The default {@link org.apache.directory.api.ldap.codec.api.LdapApiService} implementation.
 * It loads the Controls and ExtendedOperations as defined in the following system parameters :
 * <ul>
 *   <li>Controls :
 *     <ul>
 *       <li>apacheds.controls</li>
 *       <li>default.controls</li>
 *     </ul>
 *   </li>
 *   <li>ExtendedOperations :
 *     <ul>
 *       <li>apacheds.extendedOperations</li>
 *       <li>default.extendedOperation.responses</li>
 *       <li>extra.extendedOperations</li>
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

    /** The list of controls to load at startup */
    public static final String CONTROLS_LIST = "apacheds.controls";

    /** The list of extended operations to load at startup */
    public static final String EXTENDED_OPERATIONS_LIST = "apacheds.extendedOperations";

    /** The (old) list of default controls to load at startup */
    private static final String OLD_DEFAULT_CONTROLS_LIST = "default.controls";

    /** The (old) list of extra extended operations to load at startup */
    private static final String OLD_EXTRA_EXTENDED_OPERATION_LIST = "extra.extendedOperations";


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
        this( getControlsFromSystemProperties(), getExtendedOperationsFromSystemProperties() );
    }


    /**
     * Creates a new instance of StandaloneLdapApiService.
     *
     * @param controls The list of controls to store
     * @param extendedOperations The list of extended operations to store
     * @throws Exception If we had an issue with one of the two lists
     */
    public StandaloneLdapApiService( List<String> controls, List<String> extendedOperations ) throws Exception
    {
        CodecFactoryUtil.loadStockControls( getControlFactories(), this );

        CodecFactoryUtil.loadStockExtendedOperations( getExtendedOperationsFactories(), this );

        // Load the controls
        loadControls( controls );

        // Load the extended operations
        loadExtendedOperations( extendedOperations );

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
                throw new RuntimeException( "Failed to load default codec factory.", cause );
            }
        }
    }


    /**
     * Parses the system properties to obtain the controls list.
     * 
     * @throws Exception
     */
    private static List<String> getControlsFromSystemProperties() throws Exception
    {
        List<String> controlsList = new ArrayList<>();

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
        }

        return controlsList;
    }


    /**
     * Parses the system properties to obtain the extended operations.
     * Such extended operations are stored in the <b>apacheds.extendedOperations</b>
     * and <b>default.extendedOperation.requests</b> system properties.
     */
    private static List<String> getExtendedOperationsFromSystemProperties() throws Exception
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
            String oldDefaultControlsString = System.getProperty( OLD_EXTRA_EXTENDED_OPERATION_LIST );

            if ( !Strings.isEmpty( oldDefaultControlsString ) )
            {
                for ( String extendedOperation : oldDefaultControlsString.split( "," ) )
                {
                    extendedOperationsList.add( extendedOperation );
                }
            }
        }

        return extendedOperationsList;
    }


    /**
     * Loads a list of controls from their FQCN.
     */
    private void loadControls( List<String> controlsList ) throws Exception
    {
        // Adding all controls
        if ( !controlsList.isEmpty() )
        {
            for ( String controlFQCN : controlsList )
            {
                loadControl( controlFQCN );
            }
        }
    }


    /**
     * Loads a control from its FQCN.
     */
    private void loadControl( String controlFQCN ) throws Exception
    {
        if ( getControlFactories().containsKey( controlFQCN ) )
        {
            LOG.debug( "Factory for control {} was already loaded", controlFQCN );
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

        ControlFactory<?> factory = ( ControlFactory<?> ) constructor.newInstance( new Object[]
            { this } );
        getControlFactories().put( factory.getOid(), factory );

        LOG.info( "Registered control factory: {}", factory.getOid() );
    }


    /**
     * Loads a list of extended operation from their FQCN
     */
    private void loadExtendedOperations( List<String> extendedOperationsList ) throws Exception
    {
        // Adding all extended operations
        if ( !extendedOperationsList.isEmpty() )
        {
            for ( String extendedOperationFQCN : extendedOperationsList )
            {
                loadExtendedOperation( extendedOperationFQCN );
            }
        }
    }


    /**
     * Loads an of extended operations from its FQCN
     */
    private void loadExtendedOperation( String extendedOperationFQCN ) throws Exception
    {
        if ( getExtendedOperationsFactories().containsKey( extendedOperationFQCN ) )
        {
            LOG.debug( "Factory for extended operation {} was already loaded", extendedOperationFQCN );
            return;
        }

        Class<?>[] types = new Class<?>[]
            { LdapApiService.class };

        // note, trimming whitespace doesn't hurt as it is a class name and
        // helps DI containers that use xml config as xml ignores whitespace
        @SuppressWarnings("unchecked")
        Class<? extends ExtendedOperationFactory> clazz = ( Class<? extends ExtendedOperationFactory> ) Class
            .forName( extendedOperationFQCN.trim() );
        Constructor<?> constructor = clazz.getConstructor( types );

        ExtendedOperationFactory factory = ( ExtendedOperationFactory ) constructor
            .newInstance( new Object[]
                { this } );
        getExtendedOperationsFactories().put( factory.getOid(), factory );

        LOG.info( "Registered pre-bundled extended operation factory: {}", factory.getOid() );
    }
}
