/*
 * Copyright (c) 2014, Oracle America, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *  * Neither the name of Oracle nor the names of its contributors may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.apache.directory;

import java.util.Collections;
import java.util.List;

//import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.openjdk.jmh.annotations.Benchmark;

public class MyBenchmark 
{
    private static SchemaManager schemaManager;
    private static StringBuilder sb = new StringBuilder( "AZERTYUIOPQSDFGJKL" );
    private static Dn dn1;
    private static Dn dn2;
    
    static
    {
        schemaManager = new DefaultSchemaManager();
        
        List<Logger> loggers = Collections.<Logger>list( LogManager.getCurrentLoggers() );
        loggers.add( LogManager.getRootLogger() );
        
        for ( Logger logger : loggers ) 
        {
            logger.setLevel( Level.OFF );
        }
        
        try
        {
            dn1 = new Dn( schemaManager, "cn=elecharny,dc=symas,dc=com" );
            dn2 = new Dn( schemaManager, "cn=elecharnu,dc=symas,dc=com" );
        }
        catch ( LdapInvalidDnException e )
        {
            e.printStackTrace();
        }
    }
    
    private void exch( int[] indices, int x, int y )
    {
        int tmp = indices[x];
        indices[x] = indices[y];
        indices[y] = tmp;
    }
    
    
    private int getValue( int[] values, int[] indices, int pos )
    {
        return values[indices[pos]];
    }
    
    
    private int comp( int a, int b )
    {
        return a - b;
    }
    
    private int slap_sort_vals( int[] values, int small )
    {
        int[] istack = new int[16];
        int i, j, k, left, right, jstack, match, indices[], itmp, rc = 0;
        int nvals = values.length;
        int is_norm;
        int a, cv[];

        /*
        #define SWAP(a,b,tmp)   tmp=(a);(a)=(b);(b)=tmp
        #define COMP(a,b)   match=0; rc = ordered_value_match( &match, \
                                attributeDescription, matchingRule, SLAP_MR_EQUALITY \
                                        | SLAP_MR_VALUE_OF_ASSERTION_SYNTAX \
                                        | SLAP_MR_ASSERTED_VALUE_NORMALIZED_MATCH \
                                        | SLAP_MR_ATTRIBUTE_VALUE_NORMALIZED_MATCH, \
                                        &(a), &(b), text );
         */
            
        if ( nvals <= 1 )
        {   
            return 0;
        }

        /* record indices to preserve input ordering */
        indices = new int[ nvals ];
        
        for (i=0; i<nvals; i++) 
        {
            indices[i] = i;
        }

        right = nvals-1;
        left = 0;
        jstack = 0;

        for(;;) 
        {
            if (right - left < 8) 
            {   /* Insertion sort */
                match=1;
                
                for (j=left+1;j<=right;j++) 
                {
                    itmp = indices[j]; 
                    a = values[itmp];
                    
                    for (i=j-1;i>=0;i--) 
                    {
                        COMP(cv[indices[i]], a);
                        
                        if ( match <= 0 )
                        {
                            break;
                        }
                        
                        indices[i+1] = indices[i]
                    }
                    
                    indices[i+1] = itmp;
                    
                    if ( match == 0 ) 
                    {
                        goto done;
                    }
                }
                
                if ( jstack == 0 )
                {
                    break;
                }
                    
                right = istack[jstack--];
                left = istack[jstack--];
            } 
            else 
            {
                k = (left + right) >> 1;    /* Choose median of left, center, right */
                SWAP(indices[k],indices[left+1],itmp);
                COMP( cv[indices[left]], cv[indices[right]] );
                
                if ( match > 0 ) 
                {
                    SWAP(indices[left],indices[right],itmp);
                } 
                else if ( match == 0 ) 
                {
                    i = right;
                    break;
                }
                
                COMP( cv[indices[left+1]], cv[indices[right]] );
                
                if ( match > 0 ) 
                {
                    SWAP(indices[left+1],indices[right],itmp);
                } 
                else if ( match == 0 ) 
                {
                    i = right;
                    break;
                }
                
                COMP( cv[indices[left]], cv[indices[left+1]] );
                
                if ( match > 0 ) 
                {
                    SWAP(indices[left],indices[left+1],itmp);
                } 
                else if ( match == 0 ) 
                {
                    i = left;
                    break;
                }
                
                i = left+1;
                j = right;
                a = cv[indices[i]];
                
                for(;;) 
                {
                    do 
                    {
                        i++;
                        COMP( cv[indices[i]], a );
                    } 
                    while( match < 0 );
                    
                    while( match > 0 ) 
                    {
                        j--;
                        COMP( cv[indices[j]], a );
                    }
                    
                    if (j < i) 
                    {
                        match = 1;
                        break;
                    }
                    
                    if ( match == 0 ) 
                    {
                        i = left+1;
                        break;
                    }
                    
                    SWAP(indices[i],indices[j],itmp);
                }
                
                if ( match == 0 )
                {
                    break;
                }
                
                SWAP(indices[left+1],indices[j],itmp);
                jstack += 2;
                
                if (right-i+1 > j-left) 
                {
                    istack[jstack] = right;
                    istack[jstack-1] = i;
                    right = j;
                } 
                else 
                {
                    istack[jstack] = j;
                    istack[jstack-1] = left;
                    left = i;
                }
            }
        }
        
    done:
        if ( match == 0 && i >= 0 )
        {   
            *dup = indices[i];
        }

        /* For sorted attributes, put the values in index order */
        if ( rc == LDAP_SUCCESS && match &&
            ( attributeDescription->ad_type->sat_flags & SLAP_AT_SORTED_VAL )) 
        {
            BerVarray tmpv = slap_sl_malloc( sizeof( struct berval ) * nvals, ctx );
            
            for ( i = 0; i<nvals; i++ )
            {
                tmpv[i] = cv[indices[i]];
            }
            
            for ( i = 0; i<nvals; i++ )
            {
                cv[i] = tmpv[i];
            }
                
            /* Check if the non-normalized array needs to move too */
            if ( is_norm ) 
            {
                cv = ml->sml_values;
                
                for ( i = 0; i<nvals; i++ )
                {
                    tmpv[i] = cv[indices[i]];
                }
                    
                for ( i = 0; i<nvals; i++ )
                {
                    cv[i] = tmpv[i];
                    }
            }
            
            slap_sl_free( tmpv, ctx );
        }

        slap_sl_free( indices, ctx );

        if ( rc == LDAP_SUCCESS && match == 0 ) 
        {
            /* value exists already */
            assert( i >= 0 );
            assert( i < nvals );
            rc = LDAP_TYPE_OR_VALUE_EXISTS;
        }
            
         ret:
            return rc;
        }
    }


    @Benchmark
    public void testToLowerAscii2Method()  throws Exception
    {
        // This is a demo/sample template for building your JMH benchmarks. Edit as needed.
        // Put your benchmark code here.
        dn1.equals( dn2 );
    }
}
