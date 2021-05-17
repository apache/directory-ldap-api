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
package org.apache.directory.api.ldap.schema.loader;


import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.schema.extractor.SchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.extractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.api.util.FileUtils;
import org.apache.directory.api.util.exception.Exceptions;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;


/**
 * Tests the LdifSchemaLoader.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
@Execution( ExecutionMode.CONCURRENT )
public class LdifSchemaLoaderTest
{
    private static Path tmpFolder;

    @BeforeEach
    public void setup() throws IOException
    {
        tmpFolder = Files.createTempDirectory( LdifSchemaLoaderTest.class.getSimpleName() );
    }
    
    
    @AfterEach
    public void cleanup()
    {
        FileUtils.deleteQuietly( tmpFolder.toFile() );
    }


    @Test
    public void testLoader() throws Exception
    {
        SchemaLdifExtractor extractor = new DefaultSchemaLdifExtractor( tmpFolder.toFile() );
        extractor.extractOrCopy();

        LdifSchemaLoader loader = new LdifSchemaLoader( new File( tmpFolder.toFile(), "schema" ) );
        SchemaManager sm = new DefaultSchemaManager( loader );

        boolean loaded = sm.loadAllEnabled();

        if ( !loaded )
        {
            fail( "Schema load failed : " + Exceptions.printErrors( sm.getErrors() ) );
        }

        assertTrue( sm.getRegistries().getAttributeTypeRegistry().contains( "cn" ) );
    }
}
