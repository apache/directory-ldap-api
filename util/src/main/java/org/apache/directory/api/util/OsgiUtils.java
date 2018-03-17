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
package org.apache.directory.api.util;


import java.io.File;
import java.io.FileFilter;
import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarFile;
import java.util.jar.Manifest;

import org.apache.directory.api.i18n.I18n;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Utilities for OSGi environments and embedding OSGi containers.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class OsgiUtils
{
    /** A logger */
    private static final Logger LOG = LoggerFactory.getLogger( OsgiUtils.class );

    private OsgiUtils()
    {
    }


    /**
     * All the packages that are exported from all bundles found on the system
     * classpath. The provided filter if not null is used to prune classpath
     * elements. Any uses terms found are stripped from the bundles.
     *
     * @param filter The filter to use on the files
     * @param pkgs The set of packages to use
     * @return All the exported packages of all bundles on the classpath.
     */
    public static Set<String> getAllBundleExports( FileFilter filter, Set<String> pkgs )
    {
        if ( pkgs == null )
        {
            pkgs = new HashSet<>();
        }

        Set<File> candidates = getClasspathCandidates( filter );

        for ( File candidate : candidates )
        {
            String exports = getBundleExports( candidate );

            if ( exports == null )
            {
                LOG.debug( I18n.msg( I18n.MSG_17000_NO_EXPORT_FOUND, candidate ) );
                continue;
            }

            LOG.debug( I18n.msg( I18n.MSG_17001_PROCESSING_EXPORTS, candidate, exports ) );
            splitIntoPackages( exports, pkgs );
        }

        return pkgs;
    }


    /**
     * Splits a Package-Export OSGi Manifest Attribute value into packages
     * while stripping away the key/value properties.
     *
     * @param exports The Package-Export OSGi Manifest Attribute value.
     * @param pkgs The set that will contain the found packages.
     * @return The set of exported packages without properties.
     */
    public static Set<String> splitIntoPackages( String exports, Set<String> pkgs )
    {
        if ( pkgs == null )
        {
            pkgs = new HashSet<>();
        }

        int index = 0;
        boolean inPkg = true;
        boolean inProps = false;
        StringBuilder pkg = new StringBuilder();

        while ( index < exports.length() )
        {
            if ( inPkg && exports.charAt( index ) != ';' )
            {
                pkg.append( exports.charAt( index ) );
                index++;
            }
            else if ( inPkg && exports.charAt( index ) == ';' )
            {
                inPkg = false;
                inProps = true;

                pkgs.add( pkg.toString() );
                LOG.debug( I18n.msg( I18n.MSG_17002_ADDED_PACKAGE, pkg.toString() ) );
                pkg.setLength( 0 );

                index += 8;
            }
            else if ( inProps && exports.charAt( index ) == '"'
                && index + 1 < exports.length()
                && exports.charAt( index + 1 ) == ',' )
            {
                inPkg = true;
                inProps = false;
                index += 2;
            }
            else if ( inProps )
            {
                index++;
            }
            else
            {
                LOG.error( I18n.err( I18n.ERR_17000_UNEXPECTED_PARSER_CONDITION ) );
                throw new IllegalStateException( I18n.err( I18n.ERR_17068_SHOULD_NOT_GET_HERE ) );
            }
        }

        return pkgs;
    }


    /**
     * Get the files that fits a given filter
     *
     * @param filter The filter in use
     * @return The set of Files that match the filter
     */
    public static Set<File> getClasspathCandidates( FileFilter filter )
    {
        Set<File> candidates = new HashSet<>();
        String separator = System.getProperty( "path.separator" );
        String[] cpElements = System.getProperty( "java.class.path" ).split( separator );

        for ( String element : cpElements )
        {
            File candidate = new File( element );

            if ( candidate.isFile() )
            {
                if ( filter != null && filter.accept( candidate ) )
                {
                    candidates.add( candidate );
                    LOG.info( I18n.msg( I18n.MSG_17003_ACCEPTED_CANDIDATE_WITH_FILTER, candidate.toString() ) );
                }
                else if ( filter == null && candidate.getName().endsWith( ".jar" ) )
                {
                    candidates.add( candidate );
                    LOG.info( I18n.msg( I18n.MSG_17004_ACCEPTED_CANDIDATE_NO_FILTER, candidate.toString() ) );
                }
                else
                {
                    LOG.info( I18n.msg( I18n.MSG_17005_REJECTING_CANDIDATE, candidate.toString() ) );
                }
            }
        }

        return candidates;
    }


    /**
     * Gets the attribute value for the Export-Bundle OSGi Manifest Attribute.
     * 
     * @param bundle The absolute path to a file bundle.
     * @return The value as it appears in the Manifest, as a comma delimited
     * list of packages with possible "uses" phrases appended to each package
     * or null if the attribute does not exist.
     */
    public static String getBundleExports( File bundle )
    {
        try ( JarFile jar = new JarFile( bundle ) )
        {
            Manifest manifest = jar.getManifest();

            if ( manifest == null )
            {
                return null;
            }

            for ( Map.Entry<Object, Object> attr : manifest.getMainAttributes().entrySet() )
            {
                if ( "Export-Package".equals( attr.getKey().toString() ) )
                {
                    return attr.getValue().toString();
                }
            }

            return null;
        }
        catch ( IOException e )
        {
            String msg = I18n.err( I18n.ERR_17001_FAILED_OPEN_JAR_MANIFEST );
            LOG.error( msg, e );
            throw new RuntimeException( msg, e );
        }
    }
}
