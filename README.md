# Netki Wallet Name Resolver

![JitPack Badge](https://img.shields.io/github/tag/netkicorp/java-wns-resolver.svg?label=JitPack)

This Wallet Name resolver library allows you go resolve a Wallet Name using DNS + DNSSEC. Additionally, the library has 
built-in support for optional [TLSA Record](https://tools.ietf.org/html/rfc6698) validation for Address Service endpoints. 

This library relies on the [dnssecjava](https://github.com/ibauersachs/dnssecjava) project for DNSSEC validation of
the Wallet Name resolution as well as [TLSA Record](https://tools.ietf.org/html/rfc6698) resolution.

### Example

```java
import com.netki.WalletNameResolver;
import com.netki.exceptions.WalletNameLookupException;

public class WalletNameResolverExample {

    public static void main(String[] args) throws Exception {
    
        try {
            WalletNameResolver resolver = new WalletNameResolver();
            String result = resolver.resolve("wallet.mattdavid.xyz", "btc");
            System.out.println(String.format("Resolved BTC Address for wallet.mattdavid.xyz: %s", result));  
        } catch (WalletNameLookupException e) {
            e.printStackTrace();
        }
    
    }
    
}
```