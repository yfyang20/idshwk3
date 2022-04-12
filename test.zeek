global agent_table: table[addr] of set[string] = table();

event http_header(c: connection, is_orig: bool, name: string, value: string) 
{
    local sourceIP: addr = c$id$orig_h;
    if (c$http?$user_agent) 
    {
        local agent: string = to_lower(c$http$user_agent);
        if (sourceIP in agent_table) 
            add (agent_table[sourceIP])[agent];
        else 
            agent_table[sourceIP] = set(agent);
    }
}

event zeek_done() 
{
    for (sourceIP in agent_table) 
        if (|agent_table[sourceIP]| >= 3) 
            print(addr_to_uri(sourceIP) + " is a proxy");
}
