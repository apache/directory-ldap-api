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
package org.apache.directory.ldap.client.api;


import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;

import org.apache.directory.api.ldap.model.cursor.AbstractCursor;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.message.IntermediateResponse;
import org.apache.directory.api.ldap.model.message.IntermediateResponseImpl;
import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.SearchResultDone;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchResultEntryImpl;
import org.junit.jupiter.api.Test;


/**
 * Tests EntryCursorImpl : the cursor must make progress on every loop
 * iteration, even when the server sends a response type it does not expect
 * (typically an IntermediateResponse). Before this was fixed, a single
 * IntermediateResponse made next() spin forever on the same response object.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class EntryCursorImplTest
{
    /**
     * A minimal SearchCursor stub mimicking SearchCursorImpl semantics :
     * next() advances to the next response and returns false when exhausted,
     * get() returns the current response without advancing.
     */
    private static final class StubSearchCursor extends AbstractCursor<Response> implements SearchCursor
    {
        private final List<Response> responses;

        private int index = -1;


        StubSearchCursor( Response... responses )
        {
            this.responses = Arrays.asList( responses );
        }


        @Override
        public boolean next()
        {
            index++;

            return index < responses.size();
        }


        @Override
        public Response get()
        {
            return responses.get( index );
        }


        @Override
        public boolean available()
        {
            return ( index >= 0 ) && ( index < responses.size() );
        }


        @Override
        public boolean isDone()
        {
            return index >= responses.size();
        }


        @Override
        public SearchResultDone getSearchResultDone()
        {
            return null;
        }


        @Override
        public boolean isReferral()
        {
            return false;
        }


        @Override
        public Referral getReferral()
        {
            return null;
        }


        @Override
        public boolean isEntry()
        {
            return false;
        }


        @Override
        public Entry getEntry()
        {
            return null;
        }


        @Override
        public boolean isIntermediate()
        {
            return false;
        }


        @Override
        public IntermediateResponse getIntermediate()
        {
            return null;
        }


        @Override
        public void before( Response element )
        {
            throw new UnsupportedOperationException();
        }


        @Override
        public void after( Response element )
        {
            throw new UnsupportedOperationException();
        }


        @Override
        public void beforeFirst()
        {
            throw new UnsupportedOperationException();
        }


        @Override
        public void afterLast()
        {
            throw new UnsupportedOperationException();
        }


        @Override
        public boolean first()
        {
            throw new UnsupportedOperationException();
        }


        @Override
        public boolean last()
        {
            throw new UnsupportedOperationException();
        }


        @Override
        public boolean previous()
        {
            throw new UnsupportedOperationException();
        }
    }


    @Test
    public void testNextTerminatesOnIntermediateResponseOnly() throws Exception
    {
        IntermediateResponse intermediate = new IntermediateResponseImpl( 1, "1.3.6.1.4.1.4203.1.9.1.4" );

        try ( EntryCursorImpl cursor = new EntryCursorImpl( new StubSearchCursor( intermediate ) ) )
        {
            // Must not spin forever on the IntermediateResponse : the stream is
            // exhausted after it, so next() must return false
            assertTimeoutPreemptively( Duration.ofSeconds( 10 ),
                () -> assertFalse( cursor.next() ) );
        }
    }


    @Test
    public void testNextSkipsIntermediateResponseAndReturnsEntry() throws Exception
    {
        IntermediateResponse intermediate = new IntermediateResponseImpl( 1, "1.3.6.1.4.1.4203.1.9.1.4" );

        SearchResultEntry searchResultEntry = new SearchResultEntryImpl( 1 );
        searchResultEntry.setEntry( new DefaultEntry() );

        try ( EntryCursorImpl cursor = new EntryCursorImpl( new StubSearchCursor( intermediate, searchResultEntry ) ) )
        {
            // The IntermediateResponse must be skipped, and the following entry returned
            assertTimeoutPreemptively( Duration.ofSeconds( 10 ),
                () ->
                {
                    assertTrue( cursor.next() );
                    assertNotNull( cursor.get() );
                    assertFalse( cursor.next() );
                } );
    	}
    }
}