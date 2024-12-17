/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    https://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.directory.api.ldap.model.schema.comparators;


import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Test the BitString comparator
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class BitStringComparatorTest
{
    private BitStringComparator comparator;


    @BeforeEach
    public void init()
    {
        comparator = new BitStringComparator( null );
    }


    @Test
    public void testNullBitString()
    {
        assertEquals( 0, comparator.compare( null, null ) );
        assertEquals( -1, comparator.compare( null, "0101B" ) );
        assertEquals( -1, comparator.compare( null, "000B" ) );
        assertEquals( 1, comparator.compare( "0101B", null ) );
        assertEquals( 1, comparator.compare( "111B", null ) );
    }


    @Test
    public void testBitStringsEquals()
    {
        assertEquals( 0, comparator.compare( "0B", "0B" ) );
        assertEquals( 0, comparator.compare( "1B", "1B" ) );
        assertEquals( 0, comparator.compare( "101010B", "101010B" ) );
        assertEquals( 0, comparator.compare( "00000101010B", "00101010B" ) );
    }


    @Test
    public void testBitStringsNotEquals()
    {
        assertEquals( -1, comparator.compare( "0B", "1B" ) );
        assertEquals( 1, comparator.compare( "1B", "0B" ) );
        assertEquals( 1, comparator.compare( "101110B", "101010B" ) );
        assertEquals( -1, comparator.compare( "00000101010B", "00111010B" ) );
    }
}
