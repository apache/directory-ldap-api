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
package org.apache.directory.api.util.exception;


import java.io.PrintStream;
import java.io.PrintWriter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;


/**
 * This exception is thrown when Base class for nested exceptions.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class MultiException extends Exception
{
    /** The serialVersionUID. */
    private static final long serialVersionUID = 2889747406899775761L;

    /** Collection of nested exceptions. */
    private final Collection<Throwable> nestedExceptions = new ArrayList<>();


    /**
     * Constructs an Exception without a message.
     */
    public MultiException()
    {
        super();
    }


    /**
     * Constructs an Exception with a detailed message.
     * 
     * @param message The message associated with the exception.
     */
    public MultiException( String message )
    {
        super( message );
    }


    /**
     * Lists the nested exceptions that this Exception encapsulates.
     * 
     * @return an Iterator over the nested exceptions.
     */
    public Iterator<Throwable> listNestedExceptions()
    {
        return nestedExceptions.iterator();
    }


    /**
     * Gets the size of this nested exception which equals the number of
     * exception nested within.
     * 
     * @return the size of this nested exception.
     */
    public int size()
    {
        return nestedExceptions.size();
    }


    /**
     * Tests to see if there are any nested exceptions within this
     * MultiException.
     * 
     * @return true if no exceptions are nested, false otherwise.
     */
    public boolean isEmpty()
    {
        return nestedExceptions.isEmpty();
    }


    /**
     * Add an exception to this multiexception.
     * 
     * @param nested exception to add to this MultiException.
     */
    public void addThrowable( Throwable nested )
    {
        nestedExceptions.add( nested );
    }


    // ///////////////////////////////////////////
    // Overriden Throwable Stack Trace Methods //
    // ///////////////////////////////////////////

    /**
     * Beside printing out the standard stack trace this method prints out the
     * stack traces of all the nested exceptions.
     * 
     * @param out PrintWriter to write the nested stack trace to.
     */
    @Override
    public void printStackTrace( PrintWriter out )
    {
        super.printStackTrace( out );

        out.println( "Nested exceptions to follow:\n" );
        boolean isFirst = true;

        for ( Throwable throwable : nestedExceptions )
        {
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                out.println( "\n\t<<========= Next Nested Exception" + " ========>>\n" );
            }

            throwable.printStackTrace( out );
        }

        out.println( "\n\t<<========= Last Nested Exception" + " ========>>\n" );
    }


    /**
     * Beside printing out the standard stack trace this method prints out the
     * stack traces of all the nested exceptions.
     * 
     * @param out PrintStream to write the nested stack trace to.
     */
    @Override
    public void printStackTrace( PrintStream out )
    {
        super.printStackTrace( out );

        out.println( "Nested exceptions to follow:\n" );
        boolean isFirst = true;

        for ( Throwable throwable : nestedExceptions )
        {
            if ( isFirst )
            {
                isFirst = false;
            }
            else
            {
                out.println( "\n\t<<========= Next Nested Exception" + " ========>>\n" );
            }

            throwable.printStackTrace( out );
        }

        out.println( "\n\t<<========= Last Nested Exception" + " ========>>\n" );
    }


    /**
     * Beside printing out the standard stack trace this method prints out the
     * stack traces of all the nested exceptions using standard error.
     */
    @Override
    public void printStackTrace()
    {
        this.printStackTrace( System.err );
    }
}
