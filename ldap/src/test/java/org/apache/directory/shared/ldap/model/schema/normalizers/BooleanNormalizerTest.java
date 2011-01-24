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
package org.apache.directory.shared.ldap.model.schema.normalizers;


import org.apache.directory.junit.tools.Concurrent;
import org.apache.directory.junit.tools.ConcurrentJunitRunner;
import org.apache.directory.shared.ldap.model.entry.BinaryValue;
import org.apache.directory.shared.ldap.model.entry.Value;
import org.apache.directory.shared.ldap.model.schema.normalizers.BooleanNormalizer;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;


/**
 * 
 * BooleanNormalizerTest.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@RunWith(ConcurrentJunitRunner.class)
@Concurrent()
public class BooleanNormalizerTest
{
    BooleanNormalizer normalizer = new BooleanNormalizer();


    @Test
    public void testNormalizeNullValue() throws Exception
    {
        assertNull( normalizer.normalize( (Value<?>)null ) );
    }


    @Test
    public void testNormalizeNonNullValue() throws Exception
    {
        assertEquals( "TRUE", normalizer.normalize( "true" ) );
        assertEquals( "ABC", normalizer.normalize( "aBc" ) );
        assertEquals( "FALSE", normalizer.normalize( "falsE" ) );
    }


    @Test
    public void testNormalizeValueWithSpaces() throws Exception
    {
        assertEquals( "TRUE", normalizer.normalize( " tRuE " ) );
    }


    @Test
    public void testNormalizeByteValue() throws Exception
    {
        assertEquals( "TRUE", normalizer.normalize( new BinaryValue( "tRuE".getBytes() ) ).getString() );
        assertEquals( "TRUE", normalizer.normalize( new BinaryValue( "true".getBytes() ) ).getString() );
    }

}