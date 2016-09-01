/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.directory.api.ldap.model.cursor;


import java.io.IOException;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.Loggers;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A simple implementation of a Cursor on a {@link List}.  Optionally, the
 * Cursor may be limited to a specific range within the list.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @param <E> The element on which this cursor will iterate
 */
public class ListCursor<E> extends AbstractCursor<E>
{
    /** A dedicated log for cursors */
    private static final Logger LOG_CURSOR = LoggerFactory.getLogger( Loggers.CURSOR_LOG.getName() );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = LOG_CURSOR.isDebugEnabled();

    /** The inner List */
    private final List<E> list;

    /** The associated comparator */
    private final Comparator<E> comparator;

    /** The starting position for the cursor in the list. It can be > 0 */
    private final int start;

    /** The ending position for the cursor in the list. It can be < List.size() */
    private final int end;
    /** The current position in the list */

    private int index = -1;


    /**
     * Creates a new ListCursor with lower (inclusive) and upper (exclusive)
     * bounds.
     *
     * As with all Cursors, this ListCursor requires a successful return from
     * advance operations (next() or previous()) to properly return values
     * using the get() operation.
     *
     * @param comparator an optional comparator to use for ordering
     * @param start the lower bound index
     * @param list the list this ListCursor operates on
     * @param end the upper bound index
     */
    public ListCursor( Comparator<E> comparator, int start, List<E> list, int end )
    {
        if ( list == null )
        {
            list = Collections.emptyList();
        }

        if ( ( start < 0 ) || ( start > list.size() ) )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_02005_START_INDEX_OUT_OF_RANGE, start ) );
        }

        if ( ( end < 0 ) || ( end > list.size() ) )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_02006_END_INDEX_OUT_OF_RANGE, end ) );
        }

        // check list is not empty list since the empty list is the only situation
        // where we allow for start to equal the end: in other cases it makes no sense
        if ( !list.isEmpty() && ( start >= end ) )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_02007_START_INDEX_ABOVE_END_INDEX, start, end ) );
        }

        if ( IS_DEBUG )
        {
            LOG_CURSOR.debug( "Creating ListCursor {}", this );
        }

        this.comparator = comparator;
        this.list = list;
        this.start = start;
        this.end = end;
    }


    /**
     * Creates a new ListCursor with lower (inclusive) and upper (exclusive)
     * bounds.
     *
     * As with all Cursors, this ListCursor requires a successful return from
     * advance operations (next() or previous()) to properly return values
     * using the get() operation.
     *
     * @param start the lower bound index
     * @param list the list this ListCursor operates on
     * @param end the upper bound index
     */
    public ListCursor( int start, List<E> list, int end )
    {
        this( null, start, list, end );
    }


    /**
     * Creates a new ListCursor with a specific upper (exclusive) bound: the
     * lower (inclusive) bound defaults to 0.
     *
     * @param list the backing for this ListCursor
     * @param end the upper bound index representing the position after the
     * last element
     */
    public ListCursor( List<E> list, int end )
    {
        this( null, 0, list, end );
    }


    /**
     * Creates a new ListCursor with a specific upper (exclusive) bound: the
     * lower (inclusive) bound defaults to 0. We also provide a comparator.
     *
     * @param comparator The comparator to use for the &lt;E&gt; elements
     * @param list the backing for this ListCursor
     * @param end the upper bound index representing the position after the
     * last element
     */
    public ListCursor( Comparator<E> comparator, List<E> list, int end )
    {
        this( comparator, 0, list, end );
    }


    /**
     * Creates a new ListCursor with a lower (inclusive) bound: the upper
     * (exclusive) bound is the size of the list.
     *
     * @param start the lower (inclusive) bound index: the position of the
     * first entry
     * @param list the backing for this ListCursor
     */
    public ListCursor( int start, List<E> list )
    {
        this( null, start, list, list.size() );
    }


    /**
     * Creates a new ListCursor with a lower (inclusive) bound: the upper
     * (exclusive) bound is the size of the list. We also provide a comparator.
     *
     * @param comparator The comparator to use for the &lt;E&gt; elements
     * @param start the lower (inclusive) bound index: the position of the
     * first entry
     * @param list the backing for this ListCursor
     */
    public ListCursor( Comparator<E> comparator, int start, List<E> list )
    {
        this( comparator, start, list, list.size() );
    }


    /**
     * Creates a new ListCursor without specific bounds: the bounds are
     * acquired from the size of the list.
     *
     * @param list the backing for this ListCursor
     */
    public ListCursor( List<E> list )
    {
        this( null, 0, list, list.size() );
    }


    /**
     * Creates a new ListCursor without specific bounds: the bounds are
     * acquired from the size of the list. We also provide a comparator.
     *
     * @param comparator The comparator to use for the &lt;E&gt; elements
     * @param list the backing for this ListCursor
     */
    public ListCursor( Comparator<E> comparator, List<E> list )
    {
        this( comparator, 0, list, list.size() );
    }


    /**
     * Creates a new ListCursor without any elements.
     */
    @SuppressWarnings("unchecked")
    public ListCursor()
    {
        this( null, 0, Collections.EMPTY_LIST, 0 );
    }


    /**
     * Creates a new ListCursor without any elements. We also provide 
     * a comparator.
     * 
     * @param comparator The comparator to use for the &lt;E&gt; elements
     */
    @SuppressWarnings("unchecked")
    public ListCursor( Comparator<E> comparator )
    {
        this( comparator, 0, Collections.EMPTY_LIST, 0 );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean available()
    {
        return index >= 0 && index < end;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void before( E element ) throws LdapException, CursorException
    {
        checkNotClosed( "before()" );

        if ( comparator == null )
        {
            throw new IllegalStateException();
        }

        // handle some special cases
        if ( list.isEmpty() )
        {
            return;
        }
        else if ( list.size() == 1 )
        {
            if ( comparator.compare( element, list.get( 0 ) ) <= 0 )
            {
                beforeFirst();
            }
            else
            {
                afterLast();
            }
        }

        throw new UnsupportedOperationException( I18n.err( I18n.ERR_02008_LIST_MAY_BE_SORTED ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void after( E element ) throws LdapException, CursorException
    {
        checkNotClosed( "after()" );

        if ( comparator == null )
        {
            throw new IllegalStateException();
        }

        // handle some special cases
        if ( list.isEmpty() )
        {
            return;
        }
        else if ( list.size() == 1 )
        {
            if ( comparator.compare( element, list.get( 0 ) ) >= 0 )
            {
                afterLast();
            }
            else
            {
                beforeFirst();
            }
        }

        throw new UnsupportedOperationException( I18n.err( I18n.ERR_02008_LIST_MAY_BE_SORTED ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void beforeFirst() throws LdapException, CursorException
    {
        checkNotClosed( "beforeFirst()" );
        this.index = -1;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void afterLast() throws LdapException, CursorException
    {
        checkNotClosed( "afterLast()" );
        this.index = end;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean first() throws LdapException, CursorException
    {
        checkNotClosed( "first()" );

        if ( !list.isEmpty() )
        {
            index = start;

            return true;
        }

        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean last() throws LdapException, CursorException
    {
        checkNotClosed( "last()" );

        if ( !list.isEmpty() )
        {
            index = end - 1;

            return true;
        }

        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isFirst()
    {
        return !list.isEmpty() && index == start;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isLast()
    {
        return !list.isEmpty() && index == end - 1;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isAfterLast()
    {
        return index == end;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isBeforeFirst()
    {
        return index == -1;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean previous() throws LdapException, CursorException
    {
        checkNotClosed( "previous()" );

        // if parked at -1 we cannot go backwards
        if ( index == -1 )
        {
            return false;
        }

        // if the index moved back is still greater than or eq to start then OK
        if ( index - 1 >= start )
        {
            index--;

            return true;
        }

        // if the index currently less than or equal to start we need to park it at -1 and return false
        if ( index <= start )
        {
            index = -1;

            return false;
        }

        if ( list.isEmpty() )
        {
            index = -1;
        }

        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean next() throws LdapException, CursorException
    {
        checkNotClosed( "next()" );

        // if parked at -1 we advance to the start index and return true
        if ( !list.isEmpty() && ( index == -1 ) )
        {
            index = start;

            return true;
        }

        // if the index plus one is less than the end then increment and return true
        if ( !list.isEmpty() && ( index + 1 < end ) )
        {
            index++;

            return true;
        }

        // if the index plus one is equal to the end then increment and return false
        if ( !list.isEmpty() && ( index + 1 == end ) )
        {
            index++;

            return false;
        }

        if ( list.isEmpty() )
        {
            index = end;
        }

        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public E get() throws CursorException
    {
        checkNotClosed( "get()" );

        if ( ( index < start ) || ( index >= end ) )
        {
            throw new CursorException( I18n.err( I18n.ERR_02009_CURSOR_NOT_POSITIONED ) );
        }

        return list.get( index );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void close() throws IOException
    {
        if ( IS_DEBUG )
        {
            LOG_CURSOR.debug( "Closing ListCursor {}", this );
        }

        super.close();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void close( Exception cause ) throws IOException
    {
        if ( IS_DEBUG )
        {
            LOG_CURSOR.debug( "Closing ListCursor {}", this );
        }

        super.close( cause );
    }
}
