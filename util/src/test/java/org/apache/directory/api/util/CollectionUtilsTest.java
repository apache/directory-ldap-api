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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import org.junit.jupiter.api.Test;


/**
 * A test case for CollectionUtils. 
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
class CollectionUtilsTest
{

    @Test
    void testReverse()
    {
        List<Integer> original = Arrays.asList( 1, 2, 3 );

        Iterator<Integer> reverse = CollectionUtils.reverse( original.iterator() );

        assertTrue( reverse.hasNext() );
        assertEquals( 3, reverse.next() );
        assertTrue( reverse.hasNext() );
        assertEquals( 2, reverse.next() );
        assertTrue( reverse.hasNext() );
        assertEquals( 1, reverse.next() );
        assertFalse( reverse.hasNext() );
    }

}
