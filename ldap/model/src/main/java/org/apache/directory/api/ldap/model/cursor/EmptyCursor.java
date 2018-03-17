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

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.ldap.model.constants.Loggers;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An empty Cursor implementation.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @param <E> The type of element on which this cursor will iterate
 */
public class EmptyCursor<E> extends AbstractCursor<E>
{
    /** A dedicated log for cursors */
    private static final Logger LOG_CURSOR = LoggerFactory.getLogger( Loggers.CURSOR_LOG.getName() );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = LOG_CURSOR.isDebugEnabled();

    /**
     * Creates a new EmptyCursor instance
     */
    public EmptyCursor()
    {
        if ( IS_DEBUG )
        {
            LOG_CURSOR.debug( I18n.msg( I18n.MSG_13103_CREATING_EMPTY_CURSOR, this ) );
        }
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean available()
    {
        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void before( E element ) throws LdapException, CursorException
    {
        checkNotClosed();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void after( E element ) throws LdapException, CursorException
    {
        checkNotClosed();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void beforeFirst() throws LdapException, CursorException
    {
        checkNotClosed();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void afterLast() throws LdapException, CursorException
    {
        checkNotClosed();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean first() throws LdapException, CursorException
    {
        checkNotClosed();
        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean last() throws LdapException, CursorException
    {
        checkNotClosed();
        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean previous() throws LdapException, CursorException
    {
        checkNotClosed();
        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean next() throws LdapException, CursorException
    {
        checkNotClosed();
        return false;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public E get() throws CursorException
    {
        checkNotClosed();
        throw new InvalidCursorPositionException( I18n.err( I18n.ERR_13104_EMPTY_CURSOR ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void close() throws IOException
    {
        if ( IS_DEBUG )
        {
            LOG_CURSOR.debug( I18n.msg( I18n.MSG_13100_CLOSING_EMPTY_CURSOR, this ) );
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
            LOG_CURSOR.debug( I18n.msg( I18n.MSG_13100_CLOSING_EMPTY_CURSOR, this ) );
        }

        super.close( cause );
    }
}
