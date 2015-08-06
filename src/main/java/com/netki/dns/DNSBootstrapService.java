package com.netki.dns;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import java.net.InetAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Properties;

public class DNSBootstrapService {

    private Hashtable<?, ?> env;

    /**
     * Create DNSBootstrapService from system defaults
     */
    public DNSBootstrapService() {
        Properties env = new Properties();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        try {
            this.env = new InitialDirContext(env).getEnvironment();
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }

    /**
     * Create a DNSBootstrapService using a given environment (used for unit testing)
     * @param env Environment Hashtable to provide java.naming.provider.url configuration value
     */
    public DNSBootstrapService(Hashtable<?, ?> env) {
        this.env = env;
    }

    /**
     * Get System DNS Servers
     * @return A list of InetAddress objects contains the system's configured DNS servers
     */
    public List<InetAddress> getSystemDNSServers() {

        List<InetAddress> dnsServers = new ArrayList<>();

        try {
            String dnsProviderString = (String) this.env.get("java.naming.provider.url");
            for(String dnsUriStr : dnsProviderString.split(" ")) {
                if(dnsUriStr.equals("")) continue;
                URI dnsUri = new URI(dnsUriStr);
                dnsServers.add(InetAddress.getByName(dnsUri.getHost()));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return dnsServers;
    }

}
