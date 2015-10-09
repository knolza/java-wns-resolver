package com.netki;

import com.netki.dns.DNSBootstrapService;
import com.netki.dns.DNSUtil;
import com.netki.dnssec.DNSSECResolver;
import com.netki.exceptions.DNSSECException;
import com.netki.exceptions.WalletNameLookupException;
import com.netki.tlsa.CACertService;
import com.netki.tlsa.CertChainValidator;
import com.netki.tlsa.TLSAValidator;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.uri.BitcoinURI;
import org.bitcoinj.uri.BitcoinURIParseException;
import org.xbill.DNS.*;

import javax.net.ssl.HttpsURLConnection;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.net.*;
import java.security.KeyStoreException;
import java.util.*;

/**
 * WalletNameResolver objects are both re-usable and thread-safe.
 */

public class WalletNameResolver {

    private DNSSECResolver resolver;
    private TLSAValidator tlsaValidator;
    private int backupDnsServerIndex = 0;

    /**
     * Setup a new WalletNameResolver with default DNSSECResolver and TLSAValidator
     */
    public WalletNameResolver() {
        try {
            this.resolver = new DNSSECResolver(new DNSBootstrapService());
            this.tlsaValidator = new TLSAValidator();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
    }

    /**
     * Setup a new WalletNameResolver
     *
     * @param dnssecResolver DNSSECResolver to use for DNSSEC name resolution
     * @param tlsaValidator  TLSAValidator to use for URL Endpoint TLSA Validation
     */
    public WalletNameResolver(DNSSECResolver dnssecResolver, TLSAValidator tlsaValidator) {
        this.resolver = dnssecResolver;
        this.tlsaValidator = tlsaValidator;
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
            //BitcoinURI resolved = resolver.resolve("bip70.netki.xyz", "btc", false);
            BitcoinURI resolved = resolver.resolve("wallet.justinnewton.me", "btc", false);
            System.out.println(String.format("WalletNameResolver: %s", resolved));
        } catch (WalletNameLookupException e) {
            System.out.println("WalletNameResolverException Caught!");
            e.printStackTrace();
        }
    }

    /**
     * Set the WalletNameResolver's DNSSECResolver
     *
     * @param resolver DNSSECResolver to use for DNSSEC name resolution
     */
    public void setDNSSECResolver(DNSSECResolver resolver) {
        this.resolver = resolver;
    }

    /**
     * Set the WalletNameResolver's TLSAValidator
     *
     * @param validator TLSAValidator to use for URL Endpoint TLSA Validation
     */
    public void setTlsaValidator(TLSAValidator validator) {
        this.tlsaValidator = validator;
    }

    /**
     * Resolve a Wallet Name
     *
     * This method is thread safe as it does not depend on any externally mutable variables.
     *
     * @param label        DNS Name (i.e., wallet.mattdavid.xyz)
     * @param currency     3 Letter Code to Denote the Requested Currency (i.e., "btc", "ltc", "dgc")
     * @param validateTLSA Boolean to require TLSA validation for an URL Endpoints
     * @return Raw Cryptocurrency Address or Bitcoin URI (BIP21/BIP72)
     * @throws WalletNameLookupException Wallet Name Lookup Failure including message
     */
    public BitcoinURI resolve(String label, String currency, boolean validateTLSA) throws WalletNameLookupException {

        label = label.toLowerCase();
        currency = currency.toLowerCase();

        if (label.isEmpty()) {
            throw new WalletNameLookupException("Wallet Name Label Must Non-Empty");
        }

        String availableCurrencies;
        String resolved;

        try {
            availableCurrencies = this.resolver.resolve(String.format("_wallet.%s", DNSUtil.ensureDot(label)), Type.TXT);
            if (availableCurrencies == null || availableCurrencies.equals("")) {
                throw new WalletNameLookupException("No Wallet Name Currency List Present");
            }
        } catch (DNSSECException e) {
            if(this.backupDnsServerIndex >= this.resolver.getBackupDnsServers().size()) {
                throw new WalletNameLookupException(e.getMessage());
            }
            this.resolver.useBackupDnsServer(this.backupDnsServerIndex++);
            return this.resolve(label, currency, validateTLSA);
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
            if(this.backupDnsServerIndex >= this.resolver.getBackupDnsServers().size()) {
                throw new WalletNameLookupException(e.getMessage());
            }
            this.resolver.useBackupDnsServer(this.backupDnsServerIndex++);
            return this.resolve(label, currency, validateTLSA);
        }


        byte[] decodeResult = DatatypeConverter.parseBase64Binary(resolved);
        try {
            URL walletNameUrl = new URL(new String(decodeResult));
            return processWalletNameUrl(walletNameUrl, validateTLSA);
        } catch (MalformedURLException e) { /* This is not a URL */ }

        try {
            this.backupDnsServerIndex = 0;
            return new BitcoinURI(new MainNetParams(), resolved);
        } catch (BitcoinURIParseException e) {
            try {
                return new BitcoinURI(new MainNetParams(), "bitcoin:" + resolved);
            } catch (BitcoinURIParseException e1) {
                throw new WalletNameLookupException("BitcoinURI Creation Failed for " + resolved + ": " + e1.getMessage());
            }
        }
    }

    /**
     * Resolve a Wallet Name URL Endpoint
     *
     * @param url        Wallet Name URL Endpoint
     * @param verifyTLSA Do TLSA validation for URL Endpoint?
     * @return String data value returned by URL Endpoint
     * @throws WalletNameLookupException Wallet Name Address Service URL Processing Failure
     */
    public BitcoinURI processWalletNameUrl(URL url, boolean verifyTLSA) throws WalletNameLookupException {

        HttpsURLConnection conn = null;
        InputStream ins;
        InputStreamReader isr;
        BufferedReader in = null;

        if (verifyTLSA) {
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

            try {
                return new BitcoinURI(new MainNetParams(), data);
            } catch (BitcoinURIParseException e) {
                throw new WalletNameLookupException("Unable to create BitcoinURI: " + e.getMessage());
            }
        } catch (IOException e) {
            e.printStackTrace();
            throw new WalletNameLookupException("WalletName URL Connection Failed");
        } finally {
            if (conn != null && in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    // Do Nothing
                }
                conn.disconnect();
            }
        }
    }

}
