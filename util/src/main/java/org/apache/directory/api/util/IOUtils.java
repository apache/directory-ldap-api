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


import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;


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
     * The default buffer size ({@value}) to use for
     * {@link #copyLarge(InputStream, OutputStream)}
     * and
     * {@link #copyLarge(Reader, Writer)}
     */
    private static final int DEFAULT_BUFFER_SIZE = 1024 * 4;

    /** The end of file */
    private static final int EOF = -1;


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
     * @param closeables the objects to close, may be null or already closed
     * @since 2.5
     */
    public static void closeQuietly( Closeable... closeables )
    {
        if ( closeables == null )
        {
            return;
        }

        for ( Closeable closeable : closeables )
        {
            closeQuietly( closeable );
        }
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


    /**
    * Gets the contents of an <code>InputStream</code> as a String
    * using the specified character encoding.
    * <p>
    * This method buffers the input internally, so there is no need to use a
    * <code>BufferedInputStream</code>.
    * </p>
    * @param input  the <code>InputStream</code> to read from
    * @param encoding  the encoding to use, null means platform default
    * @return the requested String
    * @throws NullPointerException if the input is null
    * @throws IOException if an I/O error occurs
    * @since 2.3
    */
    public static String toString( InputStream input, Charset encoding ) throws IOException
    {
        StringBuilderWriter sw = new StringBuilderWriter();
        copy( input, sw, encoding );

        return sw.toString();
    }


    /**
     * Returns the given Charset or the default Charset if the given Charset is null.
     * 
     * @param charset A charset or null.
     * @return the given Charset or the default Charset if the given Charset is null
     */
    public static Charset toCharset( Charset charset )
    {
        return charset == null ? Charset.defaultCharset() : charset;
    }


    /**
     * Returns a Charset for the named charset. If the name is null, return the default Charset.
     * 
     * @param charset The name of the requested charset, may be null.
     * @return a Charset for the named charset
     */
    public static Charset toCharset( String charset )
    {
        return charset == null ? Charset.defaultCharset() : Charset.forName( charset );
    }


    /**
     * Copies bytes from an <code>InputStream</code> to chars on a
     * <code>Writer</code> using the specified character encoding.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedInputStream</code>.
     * <p>
     * This method uses {@link InputStreamReader}.
     *
     * @param input  the <code>InputStream</code> to read from
     * @param output  the <code>Writer</code> to write to
     * @param inputEncoding  the encoding to use for the input stream, null means platform default
     * @throws NullPointerException if the input or output is null
     * @throws IOException if an I/O error occurs
     * @since 2.3
     */
    public static void copy( InputStream input, Writer output, Charset inputEncoding ) throws IOException
    {
        InputStreamReader in = new InputStreamReader( input, toCharset( inputEncoding ) );
        copy( in, output );
    }


    /**
     * Copies chars from a <code>Reader</code> to a <code>Writer</code>.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedReader</code>.
     * <p>
     * Large streams (over 2GB) will return a chars copied value of
     * <code>-1</code> after the copy has completed since the correct
     * number of chars cannot be returned as an int. For large streams
     * use the <code>copyLarge(Reader, Writer)</code> method.
     *
     * @param input  the <code>Reader</code> to read from
     * @param output  the <code>Writer</code> to write to
     * @return the number of characters copied, or -1 if &gt; Integer.MAX_VALUE
     * @throws NullPointerException if the input or output is null
     * @throws IOException if an I/O error occurs
     * @since 1.1
     */
    public static int copy( Reader input, Writer output ) throws IOException
    {
        long count = copyLarge( input, output );

        if ( count > Integer.MAX_VALUE )
        {
            return -1;
        }

        return ( int ) count;
    }

    
    /**
     * Copies bytes from an <code>InputStream</code> to an
     * <code>OutputStream</code>.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedInputStream</code>.
     * <p>
     * Large streams (over 2GB) will return a bytes copied value of
     * <code>-1</code> after the copy has completed since the correct
     * number of bytes cannot be returned as an int. For large streams
     * use the <code>copyLarge(InputStream, OutputStream)</code> method.
     *
     * @param input  the <code>InputStream</code> to read from
     * @param output  the <code>OutputStream</code> to write to
     * @return the number of bytes copied, or -1 if &gt; Integer.MAX_VALUE
     * @throws NullPointerException if the input or output is null
     * @throws IOException if an I/O error occurs
     * @since 1.1
     */
    public static int copy( InputStream input, OutputStream output ) throws IOException 
    {
        long count = copyLarge( input, output );
        
        if ( count > Integer.MAX_VALUE ) 
        {
            return -1;
        }
        
        return ( int ) count;
    }
    
    
    /**
     * Copies bytes from an <code>InputStream</code> to an <code>OutputStream</code> using an internal buffer of the
     * given size.
     * <p>
     * This method buffers the input internally, so there is no need to use a <code>BufferedInputStream</code>.
     * <p>
     *
     * @param input
     *            the <code>InputStream</code> to read from
     * @param output
     *            the <code>OutputStream</code> to write to
     * @param bufferSize
     *            the bufferSize used to copy from the input to the output
     * @return the number of bytes copied
     * @throws NullPointerException
     *             if the input or output is null
     * @throws IOException
     *             if an I/O error occurs
     * @since 2.5
     */
    public static long copy( InputStream input, OutputStream output, int bufferSize ) throws IOException 
    {
        return copyLarge( input, output, new byte[bufferSize] );
    }


    /**
     * Copies chars from a large (over 2GB) <code>Reader</code> to a <code>Writer</code>.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedReader</code>.
     * <p>
     * The buffer size is given by DEFAULT_BUFFER_SIZE.
     *
     * @param input  the <code>Reader</code> to read from
     * @param output  the <code>Writer</code> to write to
     * @return the number of characters copied
     * @throws NullPointerException if the input or output is null
     * @throws IOException if an I/O error occurs
     * @since 1.3
     */
    public static long copyLarge( Reader input, Writer output ) throws IOException
    {
        return copyLarge( input, output, new char[DEFAULT_BUFFER_SIZE] );
    }
    
    
    /**
     * Copies bytes from a large (over 2GB) <code>InputStream</code> to an
     * <code>OutputStream</code>.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedInputStream</code>.
     * <p>
     * The buffer size is given by DEFAULT_BUFFER_SIZE.
     *
     * @param input  the <code>InputStream</code> to read from
     * @param output  the <code>OutputStream</code> to write to
     * @return the number of bytes copied
     * @throws NullPointerException if the input or output is null
     * @throws IOException if an I/O error occurs
     * @since 1.3
     */
    public static long copyLarge( InputStream input, OutputStream output ) throws IOException 
    {
        return copy( input, output, DEFAULT_BUFFER_SIZE );
    }

    
    /**
     * Copies bytes from a large (over 2GB) <code>InputStream</code> to an
     * <code>OutputStream</code>.
     * <p>
     * This method uses the provided buffer, so there is no need to use a
     * <code>BufferedInputStream</code>.
     * <p>
     *
     * @param input  the <code>InputStream</code> to read from
     * @param output  the <code>OutputStream</code> to write to
     * @param buffer the buffer to use for the copy
     * @return the number of bytes copied
     * @throws NullPointerException if the input or output is null
     * @throws IOException if an I/O error occurs
     * @since 2.2
     */
    public static long copyLarge( InputStream input, OutputStream output, byte[] buffer ) throws IOException 
    {
        long count = 0;
        int n = 0;
        
        while ( EOF != ( n = input.read( buffer ) ) ) 
        {
            output.write( buffer, 0, n );
            count += n;
        }
        
        return count;
    }


    /**
     * Copies chars from a large (over 2GB) <code>Reader</code> to a <code>Writer</code>.
     * <p>
     * This method uses the provided buffer, so there is no need to use a
     * <code>BufferedReader</code>.
     * <p>
     *
     * @param input  the <code>Reader</code> to read from
     * @param output  the <code>Writer</code> to write to
     * @param buffer the buffer to be used for the copy
     * @return the number of characters copied
     * @throws NullPointerException if the input or output is null
     * @throws IOException if an I/O error occurs
     * @since 2.2
     */
    public static long copyLarge( Reader input, Writer output, char[] buffer ) throws IOException
    {
        long count = 0;
        int n = 0;

        while ( EOF != ( n = input.read( buffer ) ) )
        {
            output.write( buffer, 0, n );
            count += n;
        }

        return count;
    }


    /**
     * Writes chars from a <code>String</code> to bytes on an
     * <code>OutputStream</code> using the specified character encoding.
     * <p>
     * This method uses {@link String#getBytes(String)}.
     *
     * @param data  the <code>String</code> to write, null ignored
     * @param output  the <code>OutputStream</code> to write to
     * @param encoding  the encoding to use, null means platform default
     * @throws NullPointerException if output is null
     * @throws IOException if an I/O error occurs
     * @since 2.3
     */
    public static void write( String data, OutputStream output, Charset encoding ) throws IOException
    {
        if ( data != null )
        {
            output.write( data.getBytes( toCharset( encoding ) ) );
        }
    }


    /**
     * Gets the contents of an <code>InputStream</code> as a <code>byte[]</code>.
     * Use this method instead of <code>toByteArray(InputStream)</code>
     * when <code>InputStream</code> size is known
     * @param input the <code>InputStream</code> to read from
     * @param size the size of <code>InputStream</code>
     * @return the requested byte array
     * @throws IOException if an I/O error occurs or <code>InputStream</code> size differ from parameter size
     * @throws IllegalArgumentException if size is less than zero
     * @since 2.1
     */
    public static byte[] toByteArray( InputStream input, int size ) throws IOException
    {
        if ( size < 0 )
        {
            throw new IllegalArgumentException( "Size must be equal or greater than zero: " + size );
        }

        if ( size == 0 )
        {
            return new byte[0];
        }

        byte[] data = new byte[size];
        int offset = 0;
        int readed = input.read( data, offset, size - offset );

        while ( offset < size && ( readed != EOF ) )
        {
            offset += readed;
            readed = input.read( data, offset, size - offset );
        }

        if ( offset != size )
        {
            throw new IOException( "Unexpected readed size. current: " + offset + ", excepted: " + size );
        }

        return data;
    }
    
    
    /**
     * Gets contents of an <code>InputStream</code> as a <code>byte[]</code>.
     * Use this method instead of <code>toByteArray(InputStream)</code>
     * when <code>InputStream</code> size is known.
     * <b>NOTE:</b> the method checks that the length can safely be cast to an int without truncation
     * before using {@link IOUtils#toByteArray(java.io.InputStream, int)} to read into the byte array.
     * (Arrays can have no more than Integer.MAX_VALUE entries anyway)
     *
     * @param input the <code>InputStream</code> to read from
     * @param size the size of <code>InputStream</code>
     * @return the requested byte array
     * @throws IOException if an I/O error occurs or <code>InputStream</code> size differ from parameter size
     * @throws IllegalArgumentException if size is less than zero or size is greater than Integer.MAX_VALUE
     * @see IOUtils#toByteArray(java.io.InputStream, int)
     * @since 2.1
     */
    public static byte[] toByteArray( InputStream input, long size ) throws IOException 
    {

      if ( size > Integer.MAX_VALUE ) 
      {
          throw new IllegalArgumentException( "Size cannot be greater than Integer max value: " + size );
      }

      return toByteArray( input, ( int ) size );
    }
    
    
    /**
     * Gets the contents of an <code>InputStream</code> as a list of Strings,
     * one entry per line, using the specified character encoding.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedInputStream</code>.
     *
     * @param input  the <code>InputStream</code> to read from, not null
     * @param encoding  the encoding to use, null means platform default
     * @return the list of Strings, never null
     * @throws NullPointerException if the input is null
     * @throws IOException if an I/O error occurs
     * @since 2.3
     */
    public static List<String> readLines( InputStream input, Charset encoding ) throws IOException 
    {
        InputStreamReader reader = new InputStreamReader( input, toCharset( encoding ) );
        
        return readLines( reader );
    }
    
    
    /**
     * Gets the contents of a <code>Reader</code> as a list of Strings,
     * one entry per line.
     * <p>
     * This method buffers the input internally, so there is no need to use a
     * <code>BufferedReader</code>.
     *
     * @param input  the <code>Reader</code> to read from, not null
     * @return the list of Strings, never null
     * @throws NullPointerException if the input is null
     * @throws IOException if an I/O error occurs
     * @since 1.1
     */
    public static List<String> readLines( Reader input ) throws IOException 
    {
        BufferedReader reader = toBufferedReader( input );
        List<String> list = new ArrayList<String>();
        String line = reader.readLine();
        
        while ( line != null ) 
        {
            list.add( line );
            line = reader.readLine();
        }
        
        return list;
    }

    
    /**
     * Returns the given reader if it is a {@link BufferedReader}, otherwise creates a BufferedReader from the given
     * reader.
     *
     * @param reader
     *            the reader to wrap or return (not null)
     * @return the given reader or a new {@link BufferedReader} for the given reader
     * @since 2.2
     * @throws NullPointerException if the input parameter is null
     */
    public static BufferedReader toBufferedReader( Reader reader ) 
    {
        return reader instanceof BufferedReader ? ( BufferedReader ) reader : new BufferedReader( reader );
    }
}
