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
package org.apache.directory.api.ldap.model.schema.normalizers;


import com.mycila.junit.concurrent.Concurrency;
import com.mycila.junit.concurrent.ConcurrentJunitRunner;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.normalizers.ObjectClassNormalizer;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertEquals;


/**
 * Test the ObjectClass normalizer class
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrency()
public class ObjectClassNormalizerTest
{
    @Test
    public void testObjectClassNormalizerNull() throws LdapException
    {
        Normalizer normalizer = new ObjectClassNormalizer();
        assertEquals( "", normalizer.normalize( ( String ) null ) );
    }


    @Test
    public void testObjectClassNormalizerEmpty() throws LdapException
    {
        Normalizer normalizer = new ObjectClassNormalizer();
        assertEquals( "", normalizer.normalize( "" ) );
    }


    @Test
    public void testObjectClassNormalizerOneSpace() throws LdapException
    {
        Normalizer normalizer = new ObjectClassNormalizer();
        assertEquals( "", normalizer.normalize( " " ) );
    }


    @Test
    public void testObjectClassNormalizerTwoSpaces() throws LdapException
    {
        Normalizer normalizer = new ObjectClassNormalizer();
        assertEquals( "", normalizer.normalize( "  " ) );
    }


    @Test
    public void testObjectClassNormalizerNSpaces() throws LdapException
    {
        Normalizer normalizer = new ObjectClassNormalizer();
        assertEquals( "", normalizer.normalize( "      " ) );
    }


    @Test
    public void testOneChar() throws LdapException
    {
        Normalizer normalizer = new ObjectClassNormalizer();
        assertEquals( "a", normalizer.normalize( "a" ) );
        assertEquals( "a", normalizer.normalize( "A" ) );
    }


    @Test
    public void testTwoChars() throws LdapException
    {
        Normalizer normalizer = new ObjectClassNormalizer();
        assertEquals( "aa", normalizer.normalize( "Aa" ) );
        assertEquals( "aa", normalizer.normalize( "aA" ) );
    }


    @Test
    public void testNChars() throws LdapException
    {
        Normalizer normalizer = new ObjectClassNormalizer();
        assertEquals( "abcdef", normalizer.normalize( "AbCdEf" ) );
    }


    @Test
    public void testCharsWithSpaces() throws LdapException
    {
        Normalizer normalizer = new ObjectClassNormalizer();
        assertEquals( "a", normalizer.normalize( "   A" ) );
        assertEquals( "a", normalizer.normalize( "a   " ) );
        assertEquals( "a", normalizer.normalize( "   A   " ) );
        assertEquals( "top", normalizer.normalize( "  top   " ) );
    }
}