package com.netki.dns;

import static org.junit.Assert.*;
import org.junit.Test;

import java.net.InetAddress;
import java.util.Hashtable;
import java.util.List;

public class DNSBootstrapServiceTest {

    @Test
    public void singleDnsServer() {
        Hashtable<String, String> env = new Hashtable<>();
        env.put("java.naming.provider.url", "dns://8.8.8.8");
        DNSBootstrapService testService = new DNSBootstrapService(env);

        List<InetAddress> addrs = testService.getSystemDNSServers();

        assertEquals("Validate Addr Count", 1, addrs.size());
        assertEquals("Validate Address", "8.8.8.8", addrs.get(0).getHostAddress());
    }

    @Test
    public void multipleDnsServers() {
        Hashtable<String, String> env = new Hashtable<>();
        env.put("java.naming.provider.url", "dns://8.8.8.8 dns://8.8.4.4");
        DNSBootstrapService testService = new DNSBootstrapService(env);

        List<InetAddress> addrs = testService.getSystemDNSServers();

        assertEquals("Validate Addr Count", 2, addrs.size());
        assertEquals("Validate Address", "8.8.8.8", addrs.get(0).getHostAddress());
        assertEquals("Validate Address", "8.8.4.4", addrs.get(1).getHostAddress());
    }

    @Test
    public void noDnsServers() {
        Hashtable<String, String> env = new Hashtable<>();
        env.put("java.naming.provider.url", "");
        DNSBootstrapService testService = new DNSBootstrapService(env);

        List<InetAddress> addrs = testService.getSystemDNSServers();

        assertEquals("Validate Addr Count", 0, addrs.size());
    }

}
