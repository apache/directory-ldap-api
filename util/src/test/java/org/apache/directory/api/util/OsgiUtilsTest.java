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
package org.apache.directory.api.util;


import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileFilter;
import java.util.Set;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for OsgiUtils.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class OsgiUtilsTest
{
    private static final FileFilter REJECTION_FILTER = new FileFilter()
    {
        public boolean accept( File pathname )
        {
            return false;
        }
    };

    private static final FileFilter JUNIT_SLF4J_FILTER = new FileFilter()
    {
        public boolean accept( File pathname )
        {
            return pathname.getAbsolutePath().contains( "junit" ) || pathname.getAbsolutePath().contains( "slf4j" );
        }
    };

    private static final FileFilter ONLY_ONE_FILTER = new FileFilter()
    {
        boolean isDone = false;


        public boolean accept( File pathname )
        {
            if ( isDone )
            {
                return false;
            }

            isDone = true;
            return true;
        }
    };


    @Test
    public void testSplitIntoPackageVersions()
    {
        Set<String> pkgs = OsgiUtils.splitIntoPackages(
            "org.ops4j.store.intern;uses:=\"org.ops4j.store,org.ops4j.io,org.apache.commons.logging\";"
                + "version=\"1.2.2\",org.ops4j.store;uses:=\"org.ops4j.store.intern\";version=\"1.2.2", null );

        assertTrue( pkgs.contains( "org.ops4j.store.intern" ), "org.ops4j.store.intern" );
        assertTrue( pkgs.contains( "org.ops4j.store" ), "org.ops4j.store" );

        assertEquals( 2, pkgs.size(), "Expecting 2 packages" );
    }


    @Test
    public void testSplitIntoPackages()
    {
        Set<String> pkgs = OsgiUtils.splitIntoPackages(
            "org.apache.log4j.net;uses:=\"org.apache.log4j,org.apache.log4j.spi,"
                + "javax.naming,org.apache.log4j.helpers,javax.jms,org.apache.log4j.xml,"
                + "javax.mail,javax.mail.internet,org.w3c.dom,javax.jmdns\","
                + "org.apache.log4j.jmx;uses:=\"org.apache.log4j,javax.management,"
                + "com.sun.jdmk.comm,org.apache.log4j.helpers,org.apache.log4j.spi\","
                + "org.apache.log4j.jdbc;uses:=\"org.apache.log4j,org.apache.log4j.spi\","
                + "org.apache.log4j.config;uses:=\"org.apache.log4j.helpers,org.apache.log4j,"
                + "org.apache.log4j.spi\",org.apache.log4j.helpers;uses:=\"org.apache.log4j,"
                + "org.apache.log4j.spi,org.apache.log4j.pattern\",org.apache.log4j;uses:=\""
                + "org.apache.log4j.spi,org.apache.log4j.helpers,org.apache.log4j.pattern,"
                + "org.apache.log4j.or,org.apache.log4j.config\",org.apache.log4j.or.jms;"
                + "uses:=\"org.apache.log4j.helpers,javax.jms,org.apache.log4j.or\","
                + "org.apache.log4j.nt;uses:=\"org.apache.log4j.helpers,org.apache.log4j,"
                + "org.apache.log4j.spi\",org.apache.log4j.or.sax;uses:=\"org.apache.log4j.or,"
                + "org.xml.sax\",org.apache.log4j.pattern;uses:=\"org.apache.log4j.helpers,"
                + "org.apache.log4j.spi,org.apache.log4j,org.apache.log4j.or\","
                + "org.apache.log4j.spi;uses:=\"org.apache.log4j,org.apache.log4j.helpers,"
                + "com.ibm.uvm.tools,org.apache.log4j.or\",org.apache.log4j.or;uses:=\""
                + "org.apache.log4j.helpers,org.apache.log4j.spi,org.apache.log4j\","
                + "org.apache.log4j.xml;uses:=\"javax.xml.parsers,org.w3c.dom,org.xml.sax,"
                + "org.apache.log4j.config,org.apache.log4j.helpers,org.apache.log4j,"
                + "org.apache.log4j.spi,org.apache.log4j.or\",org.apache.log4j.varia;uses:=\""
                + "org.apache.log4j.spi,org.apache.log4j,org.apache.log4j.helpers\"", null );

        assertTrue( pkgs.contains( "org.apache.log4j.net" ), "org.apache.log4j.net" );
        assertTrue( pkgs.contains( "org.apache.log4j.jmx" ), "org.apache.log4j.jmx" );
        assertTrue( pkgs.contains( "org.apache.log4j.jdbc" ), "org.apache.log4j.jdbc" );
        assertTrue( pkgs.contains( "org.apache.log4j.config" ), "org.apache.log4j.config" );
        assertTrue( pkgs.contains( "org.apache.log4j.helpers" ), "org.apache.log4j.helpers" );
        assertTrue( pkgs.contains( "org.apache.log4j" ), "org.apache.log4j" );
        assertTrue( pkgs.contains( "org.apache.log4j.or" ), "org.apache.log4j.or" );
        assertTrue( pkgs.contains( "org.apache.log4j.or.jms" ), "org.apache.log4j.or.jms" );
        assertTrue( pkgs.contains( "org.apache.log4j.or.sax" ), "org.apache.log4j.or.sax" );
        assertTrue( pkgs.contains( "org.apache.log4j.nt" ), "org.apache.log4j.nt" );
        assertTrue( pkgs.contains( "org.apache.log4j.spi" ), "org.apache.log4j.spi" );
        assertTrue( pkgs.contains( "org.apache.log4j.pattern" ), "org.apache.log4j.pattern" );
        assertTrue( pkgs.contains( "org.apache.log4j.xml" ), "org.apache.log4j.xml" );
        assertTrue( pkgs.contains( "org.apache.log4j.varia" ), "org.apache.log4j.varia" );

        assertEquals( 14, pkgs.size(), "Expecting 14 packages" );
    }


    @Test
    public void testGetClasspathCandidates()
    {
        Set<File> candidates = OsgiUtils.getClasspathCandidates( REJECTION_FILTER );
        assertEquals(  0, candidates.size(), "Should have no results with REJECTION_FILTER" );

        candidates = OsgiUtils.getClasspathCandidates( ONLY_ONE_FILTER );
        assertEquals( 1, candidates.size(), "Should have one result with ONLY_ONE_FILTER" );

        candidates = OsgiUtils.getClasspathCandidates( JUNIT_SLF4J_FILTER );
        assertTrue( candidates.size() >= 4, "Should have at least 4 results with JUNIT_SLF4J_FILTER" );

        candidates = OsgiUtils.getClasspathCandidates( null );
        assertTrue( candidates.size() >= 4, "Should have at least 4 results with no filter" );
    }


    @Test
    public void testGetAllBundleExports()
    {
        OsgiUtils.getAllBundleExports( null, null );
    }
}
