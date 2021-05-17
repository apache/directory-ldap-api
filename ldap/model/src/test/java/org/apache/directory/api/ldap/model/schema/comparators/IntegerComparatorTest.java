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
 * Test the Integer comparator
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution(ExecutionMode.CONCURRENT)
public class IntegerComparatorTest 
{
    private IntegerComparator comparator;

    @BeforeEach
    public void init()
    {
        comparator = new IntegerComparator( null );
    }

    
    @Test
    public void testNullIntegers()
    {
        assertEquals( 0, comparator.compare( null, null ) );

        String int1 = "1";
        assertEquals( -1, comparator.compare( ( String ) null, int1 ) );

        assertEquals( 1, comparator.compare( int1, ( String ) null ) );
    }

    
    @Test 
    public void testBigIntegerValues()
    {
        assertEquals( -1, comparator.compare( null, "1000000000000000000000000" ) );
        assertEquals( 1, comparator.compare( "1000000000000000000000000", null ) );
        assertEquals( 0, comparator.compare( "1000000000000000000000000", "1000000000000000000000000" ) );
        
        long t0 = System.currentTimeMillis();
        
        for ( int i = 0; i < 10000000; i++ )
        {
            assertEquals( -1, comparator.compare( "9223372036854775805", "9223372036854775806" ) );
        }
        
        long t1 = System.currentTimeMillis();
        
        System.out.println( "Delta = " + ( t1 - t0 ) );
        
            assertEquals( 1, comparator.compare( "1000000000000000000000001", "1000000000000000000000000" ) );
    }
}
