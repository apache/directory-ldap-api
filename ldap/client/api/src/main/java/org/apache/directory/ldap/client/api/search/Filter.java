package org.apache.directory.ldap.client.api.search;


interface Filter
{
    public StringBuilder build();


    public StringBuilder build( StringBuilder builder );
}