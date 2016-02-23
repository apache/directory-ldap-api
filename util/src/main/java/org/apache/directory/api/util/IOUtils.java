/*
 *   Licensed to the Apache Software Foundation (ASF) under one
 *   or more contributor license agreements.  See the NOTICE file
 *   distributed with this work for additional information
 *   regarding copyright ownership.  The ASF licenses this file
 *   to you under the Apache License, Version 2.0 (the
 *   "License"); you may not use this file except in compliance
 *   with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;

/**
 * This code comes from Apache commons.io library.
 * 
 * Origin of code: Excalibur, Alexandria, Tomcat, Commons-Utils.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class IOUtils
{
    /**
     * Creates a new instance of FileUtils.
     */
    private IOUtils()
    {
        // Nothing to do.
    }
    

    /**
    * Closes an <code>InputStream</code> unconditionally.
    * <p>
    * Equivalent to {@link InputStream#close()}, except any exceptions will be ignored.
    * This is typically used in finally blocks.
    * <p>
    * Example code:
    * <pre>
    *   byte[] data = new byte[1024];
    *   InputStream in = null;
    *   try {
    *       in = new FileInputStream("foo.txt");
    *       in.read(data);
    *       in.close(); //close errors are handled
    *   } catch (Exception e) {
    *       // error handling
    *   } finally {
    *       IOUtils.closeQuietly(in);
    *   }
    * </pre>
    *
    * @param input  the InputStream to close, may be null or already closed
    */
    public static void closeQuietly( InputStream input ) 
    {
        closeQuietly( ( Closeable ) input );
    }
    
    
    /**
     * Closes a <code>Closeable</code> unconditionally.
     * <p>
     * Equivalent to {@link Closeable#close()}, except any exceptions will be ignored. This is typically used in
     * finally blocks.
     * <p>
     * Example code:
     * 
     * <pre>
     * Closeable closeable = null;
     * try {
     *     closeable = new FileReader(&quot;foo.txt&quot;);
     *     // process closeable
     *     closeable.close();
     * } catch (Exception e) {
     *     // error handling
     * } finally {
     *     IOUtils.closeQuietly(closeable);
     * }
     * </pre>
     * 
     * Closing all streams:
     * 
     * <pre>
     * try {
     *     return IOUtils.copy(inputStream, outputStream);
     * } finally {
     *     IOUtils.closeQuietly(inputStream);
     *     IOUtils.closeQuietly(outputStream);
     * }
     * </pre>
     * 
     * @param closeable
     *            the objects to close, may be null or already closed
     * @since 2.0
     */
    public static void closeQuietly( Closeable closeable ) 
    {
        try 
        {
            if ( closeable != null ) 
            {
                closeable.close();
            }
        } 
        catch ( IOException ioe ) 
        {
            // ignore
        }
    }
}
