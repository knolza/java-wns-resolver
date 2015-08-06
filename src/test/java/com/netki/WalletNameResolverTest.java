package com.netki;

import com.netki.dnssec.DNSSECResolver;
import com.netki.exceptions.DNSSECException;
import com.netki.exceptions.WalletNameLookupException;
import com.netki.tlsa.TLSAValidator;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.xbill.DNS.Type;

import java.net.URL;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

@RunWith(PowerMockRunner.class)
@PrepareForTest(WalletNameResolver.class)
public class WalletNameResolverTest {

    DNSSECResolver mockResolver;
    TLSAValidator mockTlsaValidator;
    WalletNameResolver testObj;

    @Before
    public void setUp() {
        this.mockResolver = mock(DNSSECResolver.class);
        this.mockTlsaValidator = mock(TLSAValidator.class);
        this.testObj = mock(WalletNameResolver.class);

        try {
            when(this.testObj.resolve(anyString(), anyString(), anyBoolean())).thenCallRealMethod();
            when(this.testObj.setDNSSECResolver(any())).thenCallRealMethod();
            when(this.testObj.setTlsaValidator(any())).thenCallRealMethod();
            this.testObj.setDNSSECResolver(this.mockResolver);
            this.testObj.setTlsaValidator(this.mockTlsaValidator);
        } catch (WalletNameLookupException e) {
            e.printStackTrace();
        }
    }

    @After
    public void cleanUp() {
        reset(this.mockResolver);
        reset(this.mockTlsaValidator);
    }

    @Test
    public void resolve_GoRightAddr() {
        try {
            when(this.mockResolver.resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn("btc ltc");
            when(this.mockResolver.resolve(eq("_btc._wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn("1btcaddress");
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            String result = this.testObj.resolve("wallet.domain.com", "btc", true);
            assertEquals("1btcaddress", result);
            verify(this.mockResolver, times(2)).resolve(anyString(), eq(Type.TXT));
            verify(this.mockTlsaValidator, never()).validateTLSA(any(URL.class));
            verify(this.testObj, never()).processWalletNameUrl(any(URL.class), anyBoolean());
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void resolve_GoRightURL() {
        try {
            when(this.testObj.processWalletNameUrl(any(URL.class), anyBoolean())).thenReturn("process_result");
            when(this.mockResolver.resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn("btc ltc");
            when(this.mockResolver.resolve(eq("_btc._wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn("aHR0cHM6Ly9hZGRyZXNzaW1vLm5ldGtpLmNvbS9yZXNvbHZlLzg3NTkzNDg3NTk0Mzc1OTQzNzk4MzQ3MzQ1");
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            String result = this.testObj.resolve("wallet.domain.com", "btc", true);
            assertEquals("process_result", result);
            verify(this.mockResolver, times(2)).resolve(anyString(), eq(Type.TXT));
            verify(this.mockTlsaValidator, never()).validateTLSA(any(URL.class));
            verify(this.testObj).processWalletNameUrl(eq(new URL("https://addressimo.netki.com/resolve/87593487594375943798347345")), anyBoolean());
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void resolve_NoAvailableCurrencies() {
        try {
            when(this.mockResolver.resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn(null);
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            this.testObj.resolve("wallet.domain.com", "btc", true);
            fail("This should throw an exception");
        } catch (WalletNameLookupException e) {
            try {
                assertEquals("No Wallet Name Currency List Present", e.getMessage());
                verify(this.mockResolver, times(1)).resolve(anyString(), eq(Type.TXT));
                verify(this.mockTlsaValidator, never()).validateTLSA(any(URL.class));
                verify(this.testObj, never()).processWalletNameUrl(any(URL.class), anyBoolean());
            } catch (Exception e1) {
                fail("Failure in Test Validation: " + e1.getMessage());
            }
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void resolve_EmptyCurrencies() {
        try {
            when(this.mockResolver.resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn("");
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            this.testObj.resolve("wallet.domain.com", "btc", true);
            fail("This should throw an exception");
        } catch (WalletNameLookupException e) {
            try {
                assertEquals("No Wallet Name Currency List Present", e.getMessage());
                verify(this.mockResolver, times(1)).resolve(anyString(), eq(Type.TXT));
                verify(this.mockTlsaValidator, never()).validateTLSA(any(URL.class));
                verify(this.testObj, never()).processWalletNameUrl(any(URL.class), anyBoolean());
            } catch (Exception e1) {
                fail("Failure in Test Validation: " + e1.getMessage());
            }
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void resolve_CurrencyResolverException() {
        try {
            when(this.mockResolver.resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT))).thenThrow(new DNSSECException("message"));
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            this.testObj.resolve("wallet.domain.com", "btc", true);
            fail("This should throw an exception");
        } catch (WalletNameLookupException e) {
            try {
                assertEquals("message", e.getMessage());
                verify(this.mockResolver, times(1)).resolve(anyString(), eq(Type.TXT));
                verify(this.mockTlsaValidator, never()).validateTLSA(any(URL.class));
                verify(this.testObj, never()).processWalletNameUrl(any(URL.class), anyBoolean());
            } catch (Exception e1) {
                fail("Failure in Test Validation: " + e1.getMessage());
            }
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void resolve_CurrencyNotAvailable() {
        try {
            when(this.mockResolver.resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn("btc ltc");
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            this.testObj.resolve("wallet.domain.com", "dgc", true);
            fail("This should throw an exception");
        } catch (WalletNameLookupException e) {
            try {
                assertEquals("Currency Not Available", e.getMessage());
                verify(this.mockResolver, times(1)).resolve(anyString(), eq(Type.TXT));
                verify(this.mockTlsaValidator, never()).validateTLSA(any(URL.class));
                verify(this.testObj, never()).processWalletNameUrl(any(URL.class), anyBoolean());
            } catch (Exception e1) {
                fail("Failure in Test Validation: " + e1.getMessage());
            }
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void resolve_EmptyAddressResolution() {
        try {
            when(this.mockResolver.resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn("btc ltc");
            when(this.mockResolver.resolve(eq("_btc._wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn("");
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            this.testObj.resolve("wallet.domain.com", "btc", true);
            fail("This should throw an exception");
        } catch (WalletNameLookupException e) {
            try {
                assertEquals("Currency Not Available", e.getMessage());
                verify(this.mockResolver, times(2)).resolve(anyString(), eq(Type.TXT));
                verify(this.mockTlsaValidator, never()).validateTLSA(any(URL.class));
                verify(this.testObj, never()).processWalletNameUrl(any(URL.class), anyBoolean());
            } catch (Exception e1) {
                fail("Failure in Test Validation: " + e1.getMessage());
            }
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void resolve_AddressResolutionException() {
        try {
            when(this.mockResolver.resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn("btc ltc");
            when(this.mockResolver.resolve(eq("_btc._wallet.wallet.domain.com."), eq(Type.TXT))).thenThrow(new DNSSECException("message"));
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            this.testObj.resolve("wallet.domain.com", "btc", true);
            fail("This should throw an exception");
        } catch (WalletNameLookupException e) {
            try {
                assertEquals("message", e.getMessage());
                verify(this.mockResolver, times(2)).resolve(anyString(), eq(Type.TXT));
                verify(this.mockTlsaValidator, never()).validateTLSA(any(URL.class));
                verify(this.testObj, never()).processWalletNameUrl(any(URL.class), anyBoolean());
            } catch (Exception e1) {
                fail("Failure in Test Validation: " + e1.getMessage());
            }
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

    @Test
    public void resolve_URLException() {
        try {
            when(this.mockResolver.resolve(eq("_wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn("btc ltc");
            when(this.mockResolver.resolve(eq("_btc._wallet.wallet.domain.com."), eq(Type.TXT))).thenReturn("aHQ6JCVAcmFuZG9tVGV4dC4JYmFja3dhcmRz");
        } catch (Exception e) {
            fail("Failure to Setup Test: " + e.getMessage());
        }

        try {
            String result = this.testObj.resolve("wallet.domain.com", "btc", true);
            assertEquals("aHQ6JCVAcmFuZG9tVGV4dC4JYmFja3dhcmRz", result);
            verify(this.mockResolver, times(2)).resolve(anyString(), eq(Type.TXT));
            verify(this.mockTlsaValidator, never()).validateTLSA(any(URL.class));
            verify(this.testObj, never()).processWalletNameUrl(eq(new URL("https://addressimo.netki.com/resolve/87593487594375943798347345")), anyBoolean());
        } catch (Exception e) {
            fail("Unknown Test Failure: " + e.getMessage());
        }
    }

}
