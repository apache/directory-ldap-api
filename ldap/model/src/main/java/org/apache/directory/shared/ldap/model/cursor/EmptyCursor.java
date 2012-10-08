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
package org.apache.directory.shared.ldap.model.cursor;


import org.apache.directory.shared.i18n.I18n;
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
    private static final Logger LOG_CURSOR = LoggerFactory.getLogger( "CURSOR" );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = LOG_CURSOR.isDebugEnabled();

    public EmptyCursor()
    {
    	if ( IS_DEBUG )
    	{
    		LOG_CURSOR.debug( "Creating EmptyCursor : {}", this );
    	}
    }
    
    /**
     * {@inheritDoc}
     */
    public boolean available()
    {
        return false;
    }


    /**
     * {@inheritDoc}
     */
    public void before( E element ) throws Exception
    {
        checkNotClosed( "before()" );
    }


    /**
     * {@inheritDoc}
     */
    public void after( E element ) throws Exception
    {
        checkNotClosed( "after()" );
    }


    /**
     * {@inheritDoc}
     */
    public void beforeFirst() throws Exception
    {
        checkNotClosed( "beforeFirst()" );
    }


    /**
     * {@inheritDoc}
     */
    public void afterLast() throws Exception
    {
        checkNotClosed( "afterLast()" );
    }


    /**
     * {@inheritDoc}
     */
    public boolean first() throws Exception
    {
        checkNotClosed( "first()" );
        return false;
    }


    /**
     * {@inheritDoc}
     */
    public boolean last() throws Exception
    {
        checkNotClosed( "last()" );
        return false;
    }


    /**
     * {@inheritDoc}
     */
    public boolean previous() throws Exception
    {
        checkNotClosed( "previous()" );
        return false;
    }


    /**
     * {@inheritDoc}
     */
    public boolean next() throws Exception
    {
        checkNotClosed( "next()" );
        return false;
    }


    /**
     * {@inheritDoc}
     */
    public E get() throws Exception
    {
        checkNotClosed( "get()" );
        throw new InvalidCursorPositionException( I18n.err( I18n.ERR_02004_EMPTY_CURSOR ) );
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void close() throws Exception
    {
    	if ( IS_DEBUG )
    	{
    		LOG_CURSOR.debug( "Closing EmptyCursor {}", this );
    	}
    	
        super.close();
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public void close( Exception cause ) throws Exception
    {
    	if ( IS_DEBUG )
    	{
    		LOG_CURSOR.debug( "Closing EmptyCursor {}", this );
    	}
    	
        super.close( cause );
    }
}
