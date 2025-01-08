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
package org.apache.directory.api.util;


import java.util.ArrayDeque;
import java.util.Iterator;


/**
 * Collection and Iterator utils.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class CollectionUtils
{
    /**
     * A private constructor to avoid the creation of an instance of this class
     */
    private CollectionUtils()
    {
    }

    /**
     * A method used to create a reversed iterable element
     *  
     * @param <T> The iterable object to reverse
     * @param iterator The objet to reverse
     * @return A reversed iterator
     */
    public static <T> Iterator<T> reverse( Iterator<T> iterator )
    {
        ArrayDeque<T> deque = new ArrayDeque<>();
        while ( iterator.hasNext() )
        {
            deque.addLast( iterator.next() );
        }
        return deque.descendingIterator();
    }
}
