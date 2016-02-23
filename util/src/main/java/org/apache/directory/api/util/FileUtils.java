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
import java.io.FileNotFoundException;
import java.io.IOException;

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
     * is detected as Windows using {@link FilenameUtils#isSystemWindows()}
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
}
