package org.apache.directory.api.util.exception;


import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;


public class MultiExceptionTest
{

    private PrintStream originalOut;
    private PrintStream originalErr;


    @Before
    public void setUp()
    {
        originalOut = System.out;
        originalErr = System.err;
    }


    @After
    public void tearDown()
    {
        System.setOut( originalOut );
        System.setErr( originalErr );
    }


    @Test
    public void testPrintStacktracePrintWriterDoesNotWriteToSystemOutErr()
    {
        ByteArrayOutputStream systemOut = new ByteArrayOutputStream();
        PrintStream systemPrintStream = new PrintStream( systemOut );
        System.setOut( systemPrintStream );
        System.setErr( systemPrintStream );

        StringWriter customOut = new StringWriter();
        PrintWriter customPrintWriter = new PrintWriter( customOut );
        MultiException multiException = new MultiException( "multi" );
        multiException.addThrowable( new Exception( "nested1" ) );
        multiException.addThrowable( new Exception( "nested2" ) );
        multiException.printStackTrace( customPrintWriter );

        assertThat( customOut.toString(), containsString( "multi" ) );
        assertThat( customOut.toString(), containsString( "nested1" ) );
        assertThat( customOut.toString(), containsString( "nested2" ) );
        assertThat( systemOut.size(), equalTo( 0 ) );
    }


    @Test
    public void testPrintStacktraceToPrintStreamDoesNotWriteToSystemOutErr()
    {
        ByteArrayOutputStream systemOut = new ByteArrayOutputStream();
        PrintStream systemPrintStream = new PrintStream( systemOut );
        System.setOut( systemPrintStream );
        System.setErr( systemPrintStream );

        ByteArrayOutputStream customOut = new ByteArrayOutputStream();
        PrintStream customPrintWriter = new PrintStream( customOut );
        MultiException multiException = new MultiException( "multi" );
        multiException.addThrowable( new Exception( "nested1" ) );
        multiException.addThrowable( new Exception( "nested2" ) );
        multiException.printStackTrace( customPrintWriter );

        assertThat( customOut.toString(), containsString( "multi" ) );
        assertThat( customOut.toString(), containsString( "nested1" ) );
        assertThat( customOut.toString(), containsString( "nested2" ) );
        assertThat( systemOut.size(), equalTo( 0 ) );
    }

}
