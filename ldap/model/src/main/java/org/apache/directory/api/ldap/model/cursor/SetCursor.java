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
import java.util.Set;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.Loggers;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A simple implementation of a Cursor on a {@link Set}.  Optionally, the
 * Cursor may be limited to a specific range within the list.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @param <E> The element on which this cursor will iterate
 */
public class SetCursor<E> extends AbstractCursor<E>
{
    /** A dedicated log for cursors */
    private static final Logger LOG_CURSOR = LoggerFactory.getLogger( Loggers.CURSOR_LOG.getName() );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = LOG_CURSOR.isDebugEnabled();

    /** The inner Set */
    private final E[] set;

    /** The associated comparator */
    private final Comparator<E> comparator;

    /** The current position in the list */
    private int index = -1;

    /** A limit to what we can print */
    private static final int MAX_PRINTED_ELEMENT = 100;


    /**
     * Creates a new SetCursor.
     *
     * As with all Cursors, this SetCursor requires a successful return from
     * advance operations (next() or previous()) to properly return values
     * using the get() operation.
     *
     * @param comparator an optional comparator to use for ordering
     * @param set the Set this StCursor operates on
     */
    @SuppressWarnings("unchecked")
    public SetCursor( Comparator<E> comparator, Set<E> set )
    {
        if ( set == null )
        {
            set = Collections.EMPTY_SET;
        }

        if ( IS_DEBUG )
        {
            LOG_CURSOR.debug( "Creating SetCursor {}", this );
        }

        this.comparator = comparator;
        this.set = ( E[] ) set.toArray();
    }


    /**
     * Creates a new SetCursor
     *
     * As with all Cursors, this SetCursor requires a successful return from
     * advance operations (next() or previous()) to properly return values
     * using the get() operation.
     *
     * @param set the Set this SetCursor operates on
     */
    public SetCursor( Set<E> set )
    {
        this( null, set );
    }


    /**
     * Creates a new SetCursor without any elements.
     */
    @SuppressWarnings("unchecked")
    public SetCursor()
    {
        this( null, Collections.EMPTY_SET );
    }


    /**
     * Creates a new SetCursor without any elements. We also provide 
     * a comparator.
     * 
     * @param comparator The comparator to use for the &lt;E&gt; elements
     */
    @SuppressWarnings("unchecked")
    public SetCursor( Comparator<E> comparator )
    {
        this( comparator, Collections.EMPTY_SET );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean available()
    {
        return ( index >= 0 ) && ( index < set.length );
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
        if ( set.length == 0 )
        {
            return;
        }
        else if ( set.length == 1 )
        {
            if ( comparator.compare( element, set[0] ) <= 0 )
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
        if ( set.length == 0 )
        {
            return;
        }
        else if ( set.length == 1 )
        {
            if ( comparator.compare( element, set[0] ) >= 0 )
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
        this.index = set.length;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean first() throws LdapException, CursorException
    {
        checkNotClosed( "first()" );

        if ( set.length > 0 )
        {
            index = 0;

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

        if ( set.length > 0 )
        {
            index = set.length - 1;

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
        return ( set.length > 0 ) && ( index == 0 );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isLast()
    {
        return ( set.length > 0 ) && ( index == set.length - 1 );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isAfterLast()
    {
        return index == set.length;
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
        if ( index - 1 >= 0 )
        {
            index--;

            return true;
        }

        // if the index currently less than or equal to start we need to park it at -1 and return false
        if ( index <= 0 )
        {
            index = -1;

            return false;
        }

        if ( set.length <= 0 )
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
        if ( ( set.length > 0 ) && ( index == -1 ) )
        {
            index = 0;

            return true;
        }

        // if the index plus one is less than the end then increment and return true
        if ( ( set.length > 0 ) && ( index + 1 < set.length ) )
        {
            index++;

            return true;
        }

        // if the index plus one is equal to the end then increment and return false
        if ( ( set.length > 0 ) && ( index + 1 == set.length ) )
        {
            index++;

            return false;
        }

        if ( set.length <= 0 )
        {
            index = set.length;
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

        if ( ( index < 0 ) || ( index >= set.length ) )
        {
            throw new CursorException( I18n.err( I18n.ERR_02009_CURSOR_NOT_POSITIONED ) );
        }

        return set[index];
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


    /**
     * @see Object#toString()
     */
    @Override
    public String toString( String tabs )
    {
        StringBuilder sb = new StringBuilder();

        sb.append( tabs ).append( "SetCursor :\n" );
        sb.append( tabs ).append( "    Index : " ).append( index ).append( "\n" );

        if ( ( set != null ) && ( set.length > 0 ) )
        {
            sb.append( tabs ).append( "    Size : " ).append( set.length ).append( "\n" );

            // Don't print more than 100 elements...
            int counter = 0;

            for ( E e : set )
            {
                sb.append( tabs ).append( "    " ).append( e ).append( "\n" );
                counter++;

                if ( counter == MAX_PRINTED_ELEMENT )
                {
                    break;
                }
            }
        }

        return sb.toString();
    }


    /**
     * @see Object#toString()
     */
    @Override
    public String toString()
    {
        return toString( "" );
    }
}
