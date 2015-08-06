package com.netki.dnssec;

import com.netki.dns.DNSBootstrapService;
import com.netki.dns.DNSUtil;
import com.netki.exceptions.DNSSECException;
import org.jitsi.dnssec.validator.ValidatingResolver;
import org.xbill.DNS.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Iterator;
import java.util.List;

public class DNSSECResolver {

    private List<InetAddress> dnsServers;
    private SimpleResolver simpleResolver;
    private ValidatingResolver validatingResolver;

    static String ROOT = ". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5";

    /**
     * DNSSECResolver Constructor
     *
     * @param dnsBootstrapService DNSBootstrapService to provide DNS servers for lookups
     * @throws UnknownHostException Thrown if system DNS servers are not available or invalid
     */
    public DNSSECResolver(DNSBootstrapService dnsBootstrapService) throws UnknownHostException {
        this.dnsServers = dnsBootstrapService.getSystemDNSServers();
        this.simpleResolver = new SimpleResolver(this.dnsServers.get(0).getHostAddress());
        this.validatingResolver = new ValidatingResolver(this.simpleResolver);
    }

    /**
     * Set SimpleResolver to use (used for unit testing)
     * @param sr SimpleResolver to use
     */
    public void setSimpleResolver(SimpleResolver sr) {
        this.simpleResolver = sr;
        this.validatingResolver = new ValidatingResolver(sr);
    }

    /**
     * Set ValidatingResolver to use (used for unit testing)
     * @param vr ValidatingResolver to use
     */
    public void setValidatingResolver(ValidatingResolver vr) {
        this.validatingResolver = vr;
    }

    /**
     * Resolve a DNS label of type type (types can be found here: org.xbill.DNS.Type) using DNSSEC
     *
     * @param label - DNS label to resolve using DNSSEC
     * @param type - Integer of DNS RR Type (org.xbill.DNS.Type)
     * @return Resulting value string
     * @throws DNSSECException Exception thrown with appropriate message to determine the problem that occurred
     */
    public String resolve(String label, int type) throws DNSSECException {

        // Setup Resolver
        try {
            this.validatingResolver.loadTrustAnchors(new ByteArrayInputStream(ROOT.getBytes("ASCII")));
        } catch (UnknownHostException e) {
            throw new DNSSECException("Unknown DNS Host: " + this.dnsServers.get(0).getHostAddress());
        } catch (UnsupportedEncodingException e) {
            throw new DNSSECException("Unsupported Trust Anchor Encoding");
        } catch (IOException e) {
            throw new DNSSECException("Resolver Creation Exception: " + e.getMessage());
        }

        try {
            Record qr = Record.newRecord(Name.fromConstantString(DNSUtil.ensureDot(label)), type, DClass.IN);
            Message response = this.validatingResolver.send(Message.newQuery(qr));

            if (response.getHeader().getFlag(Flags.AD) && response.getRcode() == Rcode.NOERROR) {
                for (RRset set : response.getSectionRRsets(Section.ANSWER)) {
                    Iterator iter;
                    for(iter = set.rrs(); iter.hasNext(); ) {
                        Record record = (Record)iter.next();
                        if (record.getType() == type) {
                            return record.rdataToString().replace("\"","");
                        }
                    }
                }
                throw new DNSSECException("No Query Answer Received");
            }

            for (RRset set : response.getSectionRRsets(Section.ADDITIONAL)) {
                if (set.getName().equals(Name.root) && set.getType() == type && set.getDClass() == ValidatingResolver.VALIDATION_REASON_QCLASS) {
                    String exceptionMessage = ((TXTRecord) set.first()).getStrings().get(0).toString();
                    throw new DNSSECException(exceptionMessage);
                }
            }

        } catch (IOException e) {
            throw new DNSSECException("DNSSEC Lookup Failure: " + e.getMessage());
        }

        throw new DNSSECException("Unknown DNSSEC Lookup Failure");
    }
}
