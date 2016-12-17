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
import java.util.Comparator;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.Loggers;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A Cursor over a single element.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @param <E> The type of element on which this cursor will iterate
 */
public class SingletonCursor<E> extends AbstractCursor<E>
{
    /** A dedicated log for cursors */
    private static final Logger LOG_CURSOR = LoggerFactory.getLogger( Loggers.CURSOR_LOG.getName() );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = LOG_CURSOR.isDebugEnabled();

    /** A flag to tell if the cursor is set before the first element */
    private boolean beforeFirst = true;

    /** A flag to tell if the cursor is set after the last element */
    private boolean afterLast;

    /** A flag to tell if the cursor is on the element */
    private boolean onSingleton;

    /** The comparator used for this cursor. */
    private final Comparator<E> comparator;

    /** The unique element stored in the cursor */
    private final E singleton;


    /**
     * Creates a new instance of SingletonCursor.
     *
     * @param singleton The unique element to store into this cursor
     */
    public SingletonCursor( E singleton )
    {
        this( singleton, null );
    }


    /**
     * Creates a new instance of SingletonCursor, with its associated
     * comparator
     *
     * @param singleton The unique element to store into this cursor
     * @param comparator The associated comparator
     */
    public SingletonCursor( E singleton, Comparator<E> comparator )
    {
        if ( IS_DEBUG )
        {
            LOG_CURSOR.debug( "Creating SingletonCursor {}", this );
        }

        this.singleton = singleton;
        this.comparator = comparator;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean available()
    {
        return onSingleton;
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
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_02010_NO_COMPARATOR_CANT_MOVE_BEFORE ) );
        }

        int comparison = comparator.compare( singleton, element );

        if ( comparison < 0 )
        {
            first();
        }
        else
        {
            beforeFirst();
        }
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
            throw new UnsupportedOperationException( I18n.err( I18n.ERR_02011_NO_COMPARATOR_CANT_MOVE_AFTER ) );
        }

        int comparison = comparator.compare( singleton, element );

        if ( comparison > 0 )
        {
            first();
        }
        else
        {
            afterLast();
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void beforeFirst() throws LdapException, CursorException
    {
        checkNotClosed( "beforeFirst" );
        beforeFirst = true;
        afterLast = false;
        onSingleton = false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void afterLast() throws LdapException, CursorException
    {
        checkNotClosed( "afterLast" );
        beforeFirst = false;
        afterLast = true;
        onSingleton = false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean first() throws LdapException, CursorException
    {
        checkNotClosed( "first" );
        beforeFirst = false;
        onSingleton = true;
        afterLast = false;

        return true;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean last() throws LdapException, CursorException
    {
        checkNotClosed( "last" );
        beforeFirst = false;
        onSingleton = true;
        afterLast = false;

        return true;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isFirst()
    {
        return onSingleton;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isLast()
    {
        return onSingleton;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isAfterLast()
    {
        return afterLast;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isBeforeFirst()
    {
        return beforeFirst;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean previous() throws LdapException, CursorException
    {
        checkNotClosed( "previous" );

        if ( beforeFirst )
        {
            return false;
        }

        if ( afterLast )
        {
            beforeFirst = false;
            onSingleton = true;
            afterLast = false;

            return true;
        }

        // must be on the singleton
        beforeFirst = true;
        onSingleton = false;
        afterLast = false;

        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean next() throws LdapException, CursorException
    {
        checkNotClosed( "next" );

        if ( beforeFirst )
        {
            beforeFirst = false;
            onSingleton = true;
            afterLast = false;

            return true;
        }

        if ( afterLast )
        {
            return false;
        }

        // must be on the singleton
        beforeFirst = false;
        onSingleton = false;
        afterLast = true;

        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public E get() throws CursorException
    {
        checkNotClosed( "get" );

        if ( onSingleton )
        {
            return singleton;
        }

        if ( beforeFirst )
        {
            throw new InvalidCursorPositionException( I18n.err( I18n.ERR_02012_CANNOT_ACCESS_IF_BEFORE_FIRST ) );
        }
        else
        {
            throw new InvalidCursorPositionException( I18n.err( I18n.ERR_02013_CANNOT_ACCESS_IF_AFTER_LAST ) );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void close() throws IOException
    {
        if ( IS_DEBUG )
        {
            LOG_CURSOR.debug( "Closing SingletonCursor {}", this );
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
            LOG_CURSOR.debug( "Closing SingletonCursor {}", this );
        }

        super.close( cause );
    }
}
