package org.apache.directory.ldap.client.api.search;


class UnaryFilter extends AbstractFilter
{
    private Operator operator;
    private Filter filter;


    private UnaryFilter( Operator operator )
    {
        this.operator = operator;
    }


    public UnaryFilter setFilter( Filter filter )
    {
        this.filter = filter;
        return this;
    }


    public static UnaryFilter not()
    {
        return new UnaryFilter( Operator.NOT );
    }


    public static UnaryFilter not( Filter filter )
    {
        return not().setFilter( filter );
    }


    @Override
    public StringBuilder build( StringBuilder builder )
    {
        if ( filter == null )
        {
            throw new IllegalStateException( "filter not set" );
        }

        builder.append( "(" ).append( operator.operator() );
        filter.build( builder );
        return builder.append( ")" );
    }

    public static enum Operator
    {
        NOT("!");

        private String operator;


        private Operator( String operator )
        {
            this.operator = operator;
        }


        public String operator()
        {
            return operator;
        }
    }
}