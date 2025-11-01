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
package org.apache.directory.api.ldap.schema.converter;


import java.io.InputStream;
import java.io.Writer;
import java.util.List;

import org.apache.directory.api.i18n.I18n;
import org.apache.directory.api.util.exception.ParserException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A class used to translate a OpenLdap schema file to a Ldif file compatible
 * with the ApacheDS meta schema format
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public final class SchemaToLdif
{
    /** The ASF Header */
    private static final String HEADER = "#\n" + "#  Licensed to the Apache Software Foundation (ASF) under one\n"
        + "#  or more contributor license agreements.  See the NOTICE file\n"
        + "#  distributed with this work for additional information\n"
        + "#  regarding copyright ownership.  The ASF licenses this file\n"
        + "#  to you under the Apache License, Version 2.0 (the\n"
        + "#  \"License\"); you may not use this file except in compliance\n"
        + "#  with the License.  You may obtain a copy of the License at\n" + "#  \n"
        + "#    https://www.apache.org/licenses/LICENSE-2.0\n" + "#  \n"
        + "#  Unless required by applicable law or agreed to in writing,\n"
        + "#  software distributed under the License is distributed on an\n"
        + "#  \"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY\n"
        + "#  KIND, either express or implied.  See the License for the\n"
        + "#  specific language governing permissions and limitations\n" + "#  under the License. \n" + "#\n"
        + "version: 1\n" + "\n";

    /** The logger */
    private static final Logger LOG = LoggerFactory.getLogger( SchemaToLdif.class );


    /**
     * Private constructor.
     */
    private SchemaToLdif()
    {
    }


    /**
     * This method takes a list of schema and transform them to Ldif files 
     * 
     * @param schemas The list of schema to be transformed
     * @throws ParserException If we get an error while converting the schemas
     */
    public static void transform( List<Schema> schemas ) throws ParserException
    {
        // Bypass if no schemas have yet been defined 
        if ( ( schemas == null ) || schemas.isEmpty() )
        {
            if ( LOG.isWarnEnabled() )
            {
                LOG.warn( I18n.msg( I18n.MSG_15000_NO_SCHEMA_DEFINED ) );
            }
            
            return;
        }

        // Make sure schema configurations have a name field and set defaults
        // for any other missing properties of the bean: pkg and owner.
        int i = 1;

        for ( Schema schema : schemas )
        {
            if ( schema.getName() == null )
            {
                String msg = I18n.err( I18n.ERR_15000_SCHEMA_ELEMENT_NAME_REQUIRED, i );
                LOG.error( msg );
                throw new ParserException( msg );
            }

        }

        // Generate for each schema 
        for ( Schema schema : schemas )
        {
            try
            {
                if ( LOG.isInfoEnabled() )
                {
                    LOG.info( I18n.msg( I18n.MSG_15001_GENERATING_SCHEMA, schema.getName() ) );
                }
                
                generate( schema );
            }
            catch ( Exception e )
            {
                e.printStackTrace();
                throw new ParserException( I18n.err( I18n.ERR_15004_CANNOT_GENERATE_SOURCES, schema.getName(),
                    e.getMessage() ) );
            }
        }
    }


    /**
     * Generate the ldif from a schema. The schema contains the inputStream
     * and Writer.
     * 
     * @param schema The schema to transfom
     * @throws Exception If the conversion fails
     */
    private static void generate( Schema schema ) throws Exception
    {
        try ( InputStream in = schema.getInput() )
        {
            try ( Writer out = schema.getOutput() )
            {
                // First parse the schema
                SchemaParser parser = new SchemaParser();
                List<SchemaElement> elements = parser.parse( in );
        
                // Start with the header (apache licence)
                out.write( HEADER );
        
                // Iterate through each schema elemnts
                for ( SchemaElement element : elements )
                {
                    out.write( element.toLdif( schema.getName() ) );
        
                    out.write( '\n' );
                }
        
                // Done. Flush the result and close the reader and writer
                out.flush();
            }
        }
    }
}
