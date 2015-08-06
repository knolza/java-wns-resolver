package com.netki;

import com.netki.dns.DNSBootstrapService;
import com.netki.dns.DNSUtil;
import com.netki.dnssec.DNSSECResolver;
import com.netki.exceptions.DNSSECException;
import com.netki.exceptions.WalletNameLookupException;
import com.netki.tlsa.CACertService;
import com.netki.tlsa.CertChainValidator;
import com.netki.tlsa.TLSAValidator;
import org.xbill.DNS.*;

import javax.net.ssl.HttpsURLConnection;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.*;
import java.security.KeyStoreException;
import java.util.*;

public class WalletNameResolver {

    private DNSSECResolver resolver;
    private TLSAValidator tlsaValidator;

    private static final long serialVersionUID = 1286676782550316507L;
    static String ROOT = ". IN DS 19036 8 2 49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5";

    /**
     * Setup a new WalletNameResolver with default DNSSECResolver and TLSAValidator
     */
    WalletNameResolver() {
        try {
            this.resolver = new DNSSECResolver(new DNSBootstrapService());
            this.tlsaValidator = new TLSAValidator();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }

    /**
     * Setup a new WalletNameResolver
     * @param dnssecResolver DNSSECResolver to use for DNSSEC name resolution
     * @param tlsaValidator TLSAValidator to use for URL Endpoint TLSA Validation
     */
    WalletNameResolver(DNSSECResolver dnssecResolver, TLSAValidator tlsaValidator) {
        this.resolver = dnssecResolver;
        this.tlsaValidator = tlsaValidator;
    }

    /**
     * Set the WalletNameResolver's DNSSECResolver
     *
     * @param resolver DNSSECResolver to use for DNSSEC name resolution
     * @return Always return true
     */
    public boolean setDNSSECResolver(DNSSECResolver resolver) {
        this.resolver = resolver;
        return true;
    }

    /**
     * Set the WalletNameResolver's TLSAValidator
     *
     * @param validator TLSAValidator to use for URL Endpoint TLSA Validation
     * @return Always return true
     */
    public boolean setTlsaValidator(TLSAValidator validator) {
        this.tlsaValidator = validator;
        return true;
    }

    /**
     * Resolve a Wallet Name
     *
     * @param label DNS Name (i.e., wallet.mattdavid.xyz)
     * @param currency 3 Letter Code to Denote the Requested Currency (i.e., "btc", "ltc", "dgc")
     * @param validateTLSA Boolean to require TLSA validation for an URL Endpoints
     * @return Raw Cryptocurrency Address or Bitcoin URI (BIP21/BIP72)
     * @throws WalletNameLookupException Wallet Name Lookup Failure including message
     */
    public String resolve(String label, String currency, boolean validateTLSA) throws WalletNameLookupException {

        label = label.toLowerCase();
        currency = currency.toLowerCase();

        String availableCurrencies;
        String resolved;

        try {
            availableCurrencies = this.resolver.resolve(String.format("_wallet.%s", DNSUtil.ensureDot(label)), Type.TXT);
            if (availableCurrencies == null || availableCurrencies.equals("")) {
                throw new WalletNameLookupException("No Wallet Name Currency List Present");
            }
        } catch (DNSSECException e) {
            throw new WalletNameLookupException(e.getMessage());
        }

        ArrayList<String> currencies = new ArrayList<String>(Arrays.asList(availableCurrencies.split(" ")));
        if (!currencies.contains(currency)) {
            throw new WalletNameLookupException("Currency Not Available");
        }

        try {
            resolved = this.resolver.resolve(String.format("_%s._wallet.%s", currency, DNSUtil.ensureDot(label)), Type.TXT);
            if (resolved.equals("")) {
                throw new WalletNameLookupException("Currency Not Available");
            }
        } catch (DNSSECException e) {
            throw new WalletNameLookupException(e.getMessage());
        }


        byte[] decodeResult = DatatypeConverter.parseBase64Binary(resolved);
        try {
            URL walletNameUrl = new URL(new String(decodeResult));
            return processWalletNameUrl(walletNameUrl, validateTLSA);
        } catch (MalformedURLException e) { /* This is not a URL */ }

        return resolved;

    }

    /**
     * Resolve a Wallet Name URL Endpoint
     *
     * @param url Wallet Name URL Endpoint
     * @param verifyTLSA Do TLSA validation for URL Endpoint?
     * @return String data value returned by URL Endpoint
     * @throws WalletNameLookupException Wallet Name Address Service URL Processing Failure
     */
    public String processWalletNameUrl(URL url, boolean verifyTLSA) throws WalletNameLookupException {

        HttpsURLConnection conn = null;
        InputStream ins;
        InputStreamReader isr;
        BufferedReader in = null;

        if(verifyTLSA) {
            try {
                if (!this.tlsaValidator.validateTLSA(url)) {
                    throw new WalletNameLookupException("TLSA Validation Failed");
                }
            } catch (Exception e) {
                throw new WalletNameLookupException("TLSA Validation Failed: " + e.getMessage());
            }
        }

        try {
            conn = (HttpsURLConnection) url.openConnection();
            ins = conn.getInputStream();
            isr = new InputStreamReader(ins);
            in = new BufferedReader(isr);

            String inputLine;
            String data = "";
            while ((inputLine = in.readLine()) != null) {
                data += inputLine;
            }

            return data;
        } catch (IOException e) {
            e.printStackTrace();
            throw new WalletNameLookupException("WalletName URL Connection Failed");
        } finally {
            if(conn != null && in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    // Do Nothing
                }
                conn.disconnect();
            }
        }
    }

    public static void main(String[] args) {

        DNSSECResolver dnssecResolver = null;
        CACertService caCertService = null;
        CertChainValidator chainValidator = null;

        try {
            dnssecResolver = new DNSSECResolver(new DNSBootstrapService());
            caCertService = CACertService.getInstance();
            chainValidator = new CertChainValidator();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        WalletNameResolver resolver = new WalletNameResolver(dnssecResolver, new TLSAValidator(dnssecResolver, caCertService, chainValidator));
        try {
            String resolved = resolver.resolve("bip70.netki.xyz", "btc", false);
            //String resolved = resolver.processWalletNameUrl(new URL("https://good.dane.verisignlabs.com"), true);
            System.out.println(String.format("WalletNameResolver: %s", resolved));
        } catch (WalletNameLookupException e) {
            System.out.println("WalletNameResolverException Caught!");
            e.printStackTrace();
        }
    }

}
