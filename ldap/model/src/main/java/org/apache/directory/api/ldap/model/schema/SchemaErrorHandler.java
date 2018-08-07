/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 * 
 */
package org.apache.directory.api.ldap.model.schema;

import java.util.List;

import org.slf4j.Logger;


/**
 * Interface for handling errors that occur during schema processing.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public interface SchemaErrorHandler
{
    /**
     * Handle schema error. Implementation is free to log the error, ignore the error or
     * do anything else. If the error is not ignored then implementation should remember
     * the error and reflect that in its state. Other methods of this interface should
     * behave in accord with that state.
     * 
     * @param log Logger that could be used to record error messages.
     * @param message Error message.
     * @param exception Exception (if available). Exception may provide more structured description
     *                  of the error. But it may not be available for all error states. However, only
     *                  those invocations of handle() method that contain an exceptions are considered to
     *                  be errors. The implementation may ignore any invocations that do not contain exception.
     */
    void handle( Logger log, String message, Throwable exception );

    /**
     * Returns true if the implementation handled at least one error.
     * This method is used for checks whether the schema processing should proceed or
     * stop, e.g. in cases when we want to stop processing on errors.
     * 
     * @return <tt>true</tt> if at least one error was met
     */
    boolean wasError();
    
    /**
     * Returns list of handled errors.
     * 
     * @return The list of found errors
     */
    List<Throwable> getErrors();
    
    /**
     * Resets implementation state. This cleans up any recorded errors.
     */
    void reset();
}
