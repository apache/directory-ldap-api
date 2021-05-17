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

package org.apache.directory.api.util;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;

import org.apache.directory.api.i18n.I18n;


/**
 * This code comes from Apache commons.io library.
 * 
 * Origin of code: Excalibur, Alexandria, Tomcat, Commons-Utils.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class FileUtils
{
    /**
     * The Windows separator character.
     */
    private static final char WINDOWS_SEPARATOR = '\\';

    /**
     * The system separator character.
     */
    private static final char SYSTEM_SEPARATOR = File.separatorChar;

    /**
     * The number of bytes in a kilobyte.
     */
    public static final long ONE_KB = 1024;

    /**
     * The number of bytes in a megabyte.
     */
    public static final long ONE_MB = ONE_KB * ONE_KB;

    /**
     * The file copy buffer size (30 MB)
     */
    private static final long FILE_COPY_BUFFER_SIZE = ONE_MB * 30;


    /**
     * Creates a new instance of FileUtils.
     */
    private FileUtils()
    {
        // Nothing to do.
    }


    /**
     * Deletes a directory recursively.
     *
     * @param directory  directory to delete
     * @throws IOException in case deletion is unsuccessful
     */
    public static void deleteDirectory( File directory ) throws IOException
    {
        if ( !directory.exists() )
        {
            return;
        }

        if ( !isSymlink( directory ) )
        {
            cleanDirectory( directory );
        }

        if ( !directory.delete() )
        {
            throw new IOException( I18n.err( I18n.ERR_17004_UNABLE_DELETE_DIR, directory ) );
        }
    }


    /**
     * Determines whether the specified file is a Symbolic Link rather than an actual file.
     * <p>
     * Will not return true if there is a Symbolic Link anywhere in the path,
     * only if the specific file is.
     * <p>
     * <b>Note:</b> the current implementation always returns {@code false} if the system
     * is detected as Windows
     * <p>
     * For code that runs on Java 1.7 or later, use the following method instead:
     * <br>
     * {@code boolean java.nio.file.Files.isSymbolicLink(Path path)}
     * @param file the file to check
     * @return true if the file is a Symbolic Link
     * @throws IOException if an IO error occurs while checking the file
     * @since 2.0
     */
    public static boolean isSymlink( File file ) throws IOException
    {
        if ( file == null )
        {
            throw new NullPointerException( I18n.err( I18n.ERR_17005_FILE_MUST_NOT_BE_NULL ) );
        }

        if ( SYSTEM_SEPARATOR == WINDOWS_SEPARATOR )
        {
            return false;
        }

        File fileInCanonicalDir;

        if ( file.getParent() == null )
        {
            fileInCanonicalDir = file;
        }
        else
        {
            File canonicalDir = file.getParentFile().getCanonicalFile();
            fileInCanonicalDir = new File( canonicalDir, file.getName() );
        }

        return !fileInCanonicalDir.getCanonicalFile().equals( fileInCanonicalDir.getAbsoluteFile() );
    }


    /**
     * Deletes a directory recursively.
     *
     * @param directory  directory to delete
     * @throws IOException in case deletion is unsuccessful
     */
    public static void cleanDirectory( File directory ) throws IOException
    {
        if ( !directory.exists() )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_17006_DOES_NOT_EXIST, directory ) );
        }

        if ( !directory.isDirectory() )
        {
            throw new IllegalArgumentException( I18n.err( I18n.ERR_17007_IS_NOT_DIRECTORY, directory ) );
        }

        File[] files = directory.listFiles();

        if ( files == null )
        {
            // null if security restricted
            throw new IOException( I18n.err( I18n.ERR_17008_FAIL_LIST_DIR, directory ) );
        }

        IOException exception = null;

        for ( File file : files )
        {
            try
            {
                forceDelete( file );
            }
            catch ( IOException ioe )
            {
                exception = ioe;
            }
        }

        if ( null != exception )
        {
            throw exception;
        }
    }


    /**
     * Deletes a file. If file is a directory, delete it and all sub-directories.
     * <p>
     * The difference between File.delete() and this method are:
     * <ul>
     * <li>A directory to be deleted does not have to be empty.</li>
     * <li>You get exceptions when a file or directory cannot be deleted.
     *      (java.io.File methods returns a boolean)</li>
     * </ul>
     *
     * @param file  file or directory to delete, must not be {@code null}
     * @throws NullPointerException if the directory is {@code null}
     * @throws FileNotFoundException if the file was not found
     * @throws IOException in case deletion is unsuccessful
     */
    public static void forceDelete( File file ) throws IOException
    {
        if ( file.isDirectory() )
        {
            deleteDirectory( file );
        }
        else
        {
            boolean filePresent = file.exists();

            if ( !file.delete() )
            {
                if ( !filePresent )
                {
                    throw new FileNotFoundException( I18n.err( I18n.ERR_17009_FILE_DOES_NOT_EXIST, file ) );
                }

                throw new IOException( I18n.err( I18n.ERR_17010_UNABLE_DELETE_FILE, file ) );
            }
        }
    }


    /**
     * Returns the path to the system temporary directory.
     *
     * @return the path to the system temporary directory.
     *
     * @since 2.0
     */
    public static String getTempDirectoryPath()
    {
        return System.getProperty( "java.io.tmpdir" );
    }


    /**
     * Reads the contents of a file into a String using the default encoding for the VM.
     * The file is always closed.
     *
     * @param file  the file to read, must not be {@code null}
     * @return the file contents, never {@code null}
     * @throws IOException in case of an I/O error
     * @since 1.3.1
     * @deprecated 2.5 use {@link #readFileToString(File, Charset)} instead
     */
    @Deprecated
    public static String readFileToString( File file ) throws IOException
    {
        return readFileToString( file, Charset.defaultCharset() );
    }


    /**
     * Reads the contents of a file into a String.
     * The file is always closed.
     *
     * @param file  the file to read, must not be {@code null}
     * @param encoding  the encoding to use, {@code null} means platform default
     * @return the file contents, never {@code null}
     * @throws IOException in case of an I/O error
     * @since 2.3
     */
    public static String readFileToString( File file, Charset encoding ) throws IOException
    {
        InputStream in = null;

        try
        {
            in = openInputStream( file );
            return IOUtils.toString( in, IOUtils.toCharset( encoding ) );
        }
        finally
        {
            IOUtils.closeQuietly( in );
        }
    }


    /**
     * Reads the contents of a file into a String. The file is always closed.
     *
     * @param file the file to read, must not be {@code null}
     * @param encoding the encoding to use, {@code null} means platform default
     * @return the file contents, never {@code null}
     * @throws IOException in case of an I/O error
     * @since 2.3
     */
    public static String readFileToString( File file, String encoding ) throws IOException
    {
        InputStream in = null;

        try
        {
            in = openInputStream( file );
            return IOUtils.toString( in, IOUtils.toCharset( encoding ) );
        }
        finally
        {
            IOUtils.closeQuietly( in );
        }
    }


    /**
     * Opens a {@link FileInputStream} for the specified file, providing better
     * error messages than simply calling <code>new FileInputStream(file)</code>.
     * <p>
     * At the end of the method either the stream will be successfully opened,
     * or an exception will have been thrown.
     * <p>
     * An exception is thrown if the file does not exist.
     * An exception is thrown if the file object exists but is a directory.
     * An exception is thrown if the file exists but cannot be read.
     *
     * @param file  the file to open for input, must not be {@code null}
     * @return a new {@link InputStream} for the specified file
     * @throws FileNotFoundException if the file does not exist
     * @throws IOException if the file object is a directory
     * @throws IOException if the file cannot be read
     * @since 1.3
     */
    public static InputStream openInputStream( File file ) throws IOException
    {
        if ( file.exists() )
        {
            if ( file.isDirectory() )
            {
                throw new IOException( I18n.err( I18n.ERR_17011_FILE_IS_DIR, file ) );
            }

            if ( !file.canRead() )
            {
                throw new IOException( I18n.err( I18n.ERR_17012_CANNOT_READ_FILE, file ) );
            }
        }
        else
        {
            throw new FileNotFoundException( I18n.err( I18n.ERR_17013_FILE_DOES_NOT_EXIST, file ) );
        }

        return Files.newInputStream( Paths.get( file.getPath() ) );
    }


    /**
     * Writes a String to a file creating the file if it does not exist using the default encoding for the VM.
     *
     * @param file  the file to write
     * @param data  the content to write to the file
     * @throws IOException in case of an I/O error
     * @deprecated 2.5 use {@link #writeStringToFile(File, String, Charset, boolean)} instead
     */
    @Deprecated
    public static void writeStringToFile( File file, String data ) throws IOException
    {
        writeStringToFile( file, data, Charset.defaultCharset(), false );
    }


    /**
     * Writes a String to a file creating the file if it does not exist.
     *
     * NOTE: As from v1.3, the parent directories of the file will be created
     * if they do not exist.
     *
     * @param file  the file to write
     * @param data  the content to write to the file
     * @param encoding  the encoding to use, {@code null} means platform default
     * @throws IOException in case of an I/O error
     * @throws java.io.UnsupportedEncodingException if the encoding is not supported by the VM
     */
    public static void writeStringToFile( File file, String data, String encoding ) throws IOException
    {
        writeStringToFile( file, data, IOUtils.toCharset( encoding ), false );
    }


    /**
     * Writes a String to a file creating the file if it does not exist.
     *
     * @param file  the file to write
     * @param data  the content to write to the file
     * @param encoding  the encoding to use, {@code null} means platform default
     * @param append if {@code true}, then the String will be added to the
     * end of the file rather than overwriting
     * @throws IOException in case of an I/O error
     * @since 2.3
     */
    public static void writeStringToFile( File file, String data, Charset encoding, boolean append ) throws IOException
    {
        OutputStream out = null;

        try
        {
            out = openOutputStream( file, append );
            IOUtils.write( data, out, encoding );
            out.close(); // don't swallow close Exception if copy completes normally
        }
        finally
        {
            IOUtils.closeQuietly( out );
        }
    }


    /**
     * Opens a {@link FileOutputStream} for the specified file, checking and
     * creating the parent directory if it does not exist.
     * <p>
     * At the end of the method either the stream will be successfully opened,
     * or an exception will have been thrown.
     * <p>
     * The parent directory will be created if it does not exist.
     * The file will be created if it does not exist.
     * An exception is thrown if the file object exists but is a directory.
     * An exception is thrown if the file exists but cannot be written to.
     * An exception is thrown if the parent directory cannot be created.
     *
     * @param file  the file to open for output, must not be {@code null}
     * @param append if {@code true}, then bytes will be added to the
     * end of the file rather than overwriting
     * @return a new {@link OutputStream} for the specified file
     * @throws IOException if the file object is a directory
     * @throws IOException if the file cannot be written to
     * @throws IOException if a parent directory needs creating but that fails
     * @since 2.1
     */
    public static OutputStream openOutputStream( File file, boolean append ) throws IOException
    {
        if ( file.exists() )
        {
            if ( file.isDirectory() )
            {
                throw new IOException( I18n.err( I18n.ERR_17011_FILE_IS_DIR, file ) );
            }

            if ( !file.canWrite() )
            {
                throw new IOException( I18n.err( I18n.ERR_17014_CANNOT_WRITE_FILE, file ) );
            }
        }
        else
        {
            File parent = file.getParentFile();

            if ( ( parent != null ) && ( !parent.mkdirs() && !parent.isDirectory() ) )
            {
                throw new IOException( I18n.err( I18n.ERR_17015_CANNOT_CREATE_DIR, parent ) );
            }
        }

        if ( append )
        {
            return Files.newOutputStream( Paths.get( file.getPath() ), StandardOpenOption.CREATE, StandardOpenOption.APPEND );
        }
        else
        {
            return Files.newOutputStream( Paths.get( file.getPath() ) );
        }
    }


    /**
     * Returns a {@link File} representing the system temporary directory.
     *
     * @return the system temporary directory.
     *
     * @since 2.0
     */
    public static File getTempDirectory()
    {
        return new File( getTempDirectoryPath() );
    }


    /**
     * Deletes a file, never throwing an exception. If file is a directory, delete it and all sub-directories.
     * <p>
     * The difference between File.delete() and this method are:
     * <ul>
     * <li>A directory to be deleted does not have to be empty.</li>
     * <li>No exceptions are thrown when a file or directory cannot be deleted.</li>
     * </ul>
     *
     * @param file  file or directory to delete, can be {@code null}
     * @return {@code true} if the file or directory was deleted, otherwise
     * {@code false}
     *
     * @since 1.4
     */
    public static boolean deleteQuietly( File file )
    {
        if ( file == null )
        {
            return false;
        }

        try
        {
            if ( file.isDirectory() )
            {
                cleanDirectory( file );
            }
        }
        catch ( Exception ignored )
        {
        }

        try
        {
            return file.delete();
        }
        catch ( Exception ignored )
        {
            return false;
        }
    }


    /**
     * Writes a byte array to a file creating the file if it does not exist.
     * <p>
     * NOTE: As from v1.3, the parent directories of the file will be created
     * if they do not exist.
     *
     * @param file  the file to write to
     * @param data  the content to write to the file
     * @throws IOException in case of an I/O erroe
     * @since 1.1
     */
    public static void writeByteArrayToFile( final File file, final byte[] data ) throws IOException
    {
        writeByteArrayToFile( file, data, false );
    }


    /**
     * Writes a byte array to a file creating the file if it does not exist.
     *
     * @param file  the file to write to
     * @param data  the content to write to the file
     * @param append if {@code true}, then bytes will be added to the
     * end of the file rather than overwriting
     * @throws IOException in case of an I/O error
     * @since 2.1
     */
    public static void writeByteArrayToFile( File file, byte[] data, boolean append ) throws IOException
    {
        writeByteArrayToFile( file, data, 0, data.length, append );
    }


    /**
     * Writes {@code len} bytes from the specified byte array starting
     * at offset {@code off} to a file, creating the file if it does
     * not exist.
     *
     * @param file  the file to write to
     * @param data  the content to write to the file
     * @param off   the start offset in the data
     * @param len   the number of bytes to write
     * @param append if {@code true}, then bytes will be added to the
     * end of the file rather than overwriting
     * @throws IOException in case of an I/O error
     * @since 2.5
     */
    public static void writeByteArrayToFile( File file, byte[] data, int off, int len, boolean append ) throws IOException
    {
        OutputStream out = null;
        
        try
        {
            out = openOutputStream( file, append );
            out.write( data, off, len );
            out.close(); // don't swallow close Exception if copy completes normally
        }
        finally
        {
            IOUtils.closeQuietly( out );
        }
    }

    
    /**
     * Reads the contents of a file into a byte array.
     * The file is always closed.
     *
     * @param file  the file to read, must not be {@code null}
     * @return the file contents, never {@code null}
     * @throws IOException in case of an I/O error
     * @since 1.1
     */
    public static byte[] readFileToByteArray( File file ) throws IOException 
    {
        InputStream in = null;
        
        try 
        {
            in = openInputStream( file );
            return IOUtils.toByteArray( in, file.length() );
        } 
        finally 
        {
            IOUtils.closeQuietly( in );
        }
    }

    
    /**
     * Opens a {@link FileOutputStream} for the specified file, checking and
     * creating the parent directory if it does not exist.
     * <p>
     * At the end of the method either the stream will be successfully opened,
     * or an exception will have been thrown.
     * <p>
     * The parent directory will be created if it does not exist.
     * The file will be created if it does not exist.
     * An exception is thrown if the file object exists but is a directory.
     * An exception is thrown if the file exists but cannot be written to.
     * An exception is thrown if the parent directory cannot be created.
     *
     * @param file  the file to open for output, must not be {@code null}
     * @return a new {@link OutputStream} for the specified file
     * @throws IOException if the file object is a directory
     * @throws IOException if the file cannot be written to
     * @throws IOException if a parent directory needs creating but that fails
     * @since 1.3
     */
    public static OutputStream openOutputStream( File file ) throws IOException 
    {
        return openOutputStream( file, false );
    }
    
    
    /**
     * Reads the contents of a file line by line to a List of Strings using the default encoding for the VM.
     * The file is always closed.
     *
     * @param file  the file to read, must not be {@code null}
     * @return the list of Strings representing each line in the file, never {@code null}
     * @throws IOException in case of an I/O error
     * @since 1.3
     * @deprecated 2.5 use {@link #readLines(File, Charset)} instead
     */
    @Deprecated
    public static List<String> readLines( File file ) throws IOException 
    {
        return readLines( file, Charset.defaultCharset() );
    }
    
    
    /**
     * Reads the contents of a file line by line to a List of Strings.
     * The file is always closed.
     *
     * @param file  the file to read, must not be {@code null}
     * @param encoding  the encoding to use, {@code null} means platform default
     * @return the list of Strings representing each line in the file, never {@code null}
     * @throws IOException in case of an I/O error
     * @since 2.3
     */
    public static List<String> readLines( File file, Charset encoding ) throws IOException 
    {
        InputStream in = null;
        
        try 
        {
            in = openInputStream( file );
            return IOUtils.readLines( in, IOUtils.toCharset( encoding ) );
        } 
        finally 
        {
            IOUtils.closeQuietly( in );
        }
    }
}
