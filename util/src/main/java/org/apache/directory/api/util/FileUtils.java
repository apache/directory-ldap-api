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


import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.List;


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
            String message = "Unable to delete directory " + directory + ".";
            throw new IOException( message );
        }
    }


    /**
     * Determines whether the specified file is a Symbolic Link rather than an actual file.
     * <p>
     * Will not return true if there is a Symbolic Link anywhere in the path,
     * only if the specific file is.
     * <p>
     * <b>Note:</b> the current implementation always returns {@code false} if the system
     * is detected as Windows.
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
            throw new NullPointerException( "File must not be null" );
        }

        if ( SYSTEM_SEPARATOR == WINDOWS_SEPARATOR )
        {
            return false;
        }

        File fileInCanonicalDir = null;

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
            String message = directory + " does not exist";
            throw new IllegalArgumentException( message );
        }

        if ( !directory.isDirectory() )
        {
            String message = directory + " is not a directory";
            throw new IllegalArgumentException( message );
        }

        File[] files = directory.listFiles();

        if ( files == null )
        {
            // null if security restricted
            String message = "Failed to list contents of " + directory;
            throw new IOException( message );
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
                    String message = "File does not exist: " + file;
                    throw new FileNotFoundException( message );
                }

                String message = "Unable to delete file: " + file;
                throw new IOException( message );
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
     * @return a new {@link FileInputStream} for the specified file
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
                throw new IOException( "File '" + file + "' exists but is a directory" );
            }

            if ( !file.canRead() )
            {
                throw new IOException( "File '" + file + "' cannot be read" );
            }
        }
        else
        {
            throw new FileNotFoundException( "File '" + file + "' does not exist" );
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
     * @return a new {@link FileOutputStream} for the specified file
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
                throw new IOException( "File '" + file + "' exists but is a directory" );
            }

            if ( !file.canWrite() )
            {
                throw new IOException( "File '" + file + "' cannot be written to" );
            }
        }
        else
        {
            File parent = file.getParentFile();

            if ( parent != null )
            {
                if ( !parent.mkdirs() && !parent.isDirectory() )
                {
                    throw new IOException( "Directory '" + parent + "' could not be created" );
                }
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
     * Copies a file to a new location preserving the file date.
     * <p>
     * This method copies the contents of the specified source file to the
     * specified destination file. The directory holding the destination file is
     * created if it does not exist. If the destination file exists, then this
     * method will overwrite it.
     * <p>
     * <strong>Note:</strong> This method tries to preserve the file's last
     * modified date/times using {@link File#setLastModified(long)}, however
     * it is not guaranteed that the operation will succeed.
     * If the modification operation fails, no indication is provided.
     *
     * @param srcFile  an existing file to copy, must not be {@code null}
     * @param destFile  the new file, must not be {@code null}
     *
     * @throws NullPointerException if source or destination is {@code null}
     * @throws IOException if source or destination is invalid
     * @throws IOException if an IO error occurs during copying
     * @throws IOException if the output file length is not the same as the input file length after the copy completes
     * @see #copyFile(File, File, boolean)
     */
    public static void copyFile( File srcFile, File destFile ) throws IOException
    {
        copyFile( srcFile, destFile, true );
    }


    /**
     * Copies a file to a new location.
     * <p>
     * This method copies the contents of the specified source file
     * to the specified destination file.
     * The directory holding the destination file is created if it does not exist.
     * If the destination file exists, then this method will overwrite it.
     * <p>
     * <strong>Note:</strong> Setting <code>preserveFileDate</code> to
     * {@code true} tries to preserve the file's last modified
     * date/times using {@link File#setLastModified(long)}, however it is
     * not guaranteed that the operation will succeed.
     * If the modification operation fails, no indication is provided.
     *
     * @param srcFile  an existing file to copy, must not be {@code null}
     * @param destFile  the new file, must not be {@code null}
     * @param preserveFileDate  true if the file date of the copy
     *  should be the same as the original
     *
     * @throws NullPointerException if source or destination is {@code null}
     * @throws IOException if source or destination is invalid
     * @throws IOException if an IO error occurs during copying
     * @throws IOException if the output file length is not the same as the input file length after the copy completes
     */
    public static void copyFile( File srcFile, File destFile, boolean preserveFileDate ) throws IOException
    {
        if ( srcFile == null )
        {
            throw new NullPointerException( "Source must not be null" );
        }

        if ( destFile == null )
        {
            throw new NullPointerException( "Destination must not be null" );
        }

        if ( !srcFile.exists() )
        {
            throw new FileNotFoundException( "Source '" + srcFile + "' does not exist" );
        }

        if ( srcFile.isDirectory() )
        {
            throw new IOException( "Source '" + srcFile + "' exists but is a directory" );
        }

        if ( srcFile.getCanonicalPath().equals( destFile.getCanonicalPath() ) )
        {
            throw new IOException( "Source '" + srcFile + "' and destination '" + destFile + "' are the same" );
        }

        File parentFile = destFile.getParentFile();

        if ( parentFile != null )
        {
            if ( !parentFile.mkdirs() && !parentFile.isDirectory() )
            {
                throw new IOException( "Destination '" + parentFile + "' directory cannot be created" );
            }
        }

        if ( destFile.exists() && !destFile.canWrite() )
        {
            throw new IOException( "Destination '" + destFile + "' exists but is read-only" );
        }

        doCopyFile( srcFile, destFile, preserveFileDate );
    }


    /**
     * Internal copy file method.
     * This caches the original file length, and throws an IOException 
     * if the output file length is different from the current input file length.
     * So it may fail if the file changes size.
     * It may also fail with "IllegalArgumentException: Negative size" if the input file is truncated part way
     * through copying the data and the new file size is less than the current position.
     *
     * @param srcFile  the validated source file, must not be {@code null}
     * @param destFile  the validated destination file, must not be {@code null}
     * @param preserveFileDate  whether to preserve the file date
     * @throws IOException if an error occurs
     * @throws IOException if the output file length is not the same as the input file length after the copy completes
     * @throws IllegalArgumentException "Negative size" if the file is truncated so that the size is less than the position
     */
    private static void doCopyFile( File srcFile, File destFile, boolean preserveFileDate ) throws IOException
    {
        if ( destFile.exists() && destFile.isDirectory() )
        {
            throw new IOException( "Destination '" + destFile + "' exists but is a directory" );
        }

        FileInputStream fis = null;
        FileOutputStream fos = null;
        FileChannel input = null;
        FileChannel output = null;

        try
        {
            fis = ( FileInputStream ) Files.newInputStream( Paths.get( srcFile.getPath() ) );
            fos = ( FileOutputStream ) Files.newOutputStream( Paths.get( destFile.getPath() ) );
            input = fis.getChannel();
            output = fos.getChannel();
            long size = input.size(); // TODO See IO-386
            long pos = 0;
            long count = 0;

            while ( pos < size )
            {
                long remain = size - pos;
                count = remain > FILE_COPY_BUFFER_SIZE ? FILE_COPY_BUFFER_SIZE : remain;
                long bytesCopied = output.transferFrom( input, pos, count );

                if ( bytesCopied == 0 )
                { // IO-385 - can happen if file is truncated after caching the size
                    break; // ensure we don't loop forever
                }

                pos += bytesCopied;
            }
        }
        finally
        {
            IOUtils.closeQuietly( output, fos, input, fis );
        }

        long srcLen = srcFile.length(); // TODO See IO-386
        long dstLen = destFile.length(); // TODO See IO-386

        if ( srcLen != dstLen )
        {
            throw new IOException( "Failed to copy full contents from '"
                + srcFile + "' to '" + destFile + "' Expected length: " + srcLen + " Actual: " + dstLen );
        }

        if ( preserveFileDate )
        {
            destFile.setLastModified( srcFile.lastModified() );
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
     * @return a new {@link FileOutputStream} for the specified file
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
