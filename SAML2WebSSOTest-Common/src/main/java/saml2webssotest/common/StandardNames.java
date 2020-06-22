package saml2webssotest.common;

import java.util.ArrayList;
import java.util.Arrays;

/**
 * Contains some standard names used by the test framework, including the names of the cipher suites for 
 * some of the SSL protocols (retrieved from https://www.openssl.org/docs/apps/ciphers.html)
 *
 * @author RiaasM
 *
 */
public class StandardNames {
	
	public static final ArrayList<String> sslv3 = (ArrayList<String>) Arrays.asList(
			"SSL_RSA_WITH_NULL_MD5", 
			"SSL_RSA_WITH_NULL_SHA",
			"SSL_RSA_EXPORT_WITH_RC4_40_MD5",
			"SSL_RSA_WITH_RC4_128_MD5",
			"SSL_RSA_WITH_RC4_128_SHA",
			"SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
			"SSL_RSA_WITH_IDEA_CBC_SHA",
			"SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
			"SSL_RSA_WITH_DES_CBC_SHA",
			"SSL_RSA_WITH_3DES_EDE_CBC_SHA",
			"SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
			"SSL_DH_DSS_WITH_DES_CBC_SHA",
			"SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA",
			"SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
			"SSL_DH_RSA_WITH_DES_CBC_SHA",
			"SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA",
			"SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
			"SSL_DHE_DSS_WITH_DES_CBC_SHA",
			"SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
			"SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
			"SSL_DHE_RSA_WITH_DES_CBC_SHA",
			"SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
			"SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",
			"SSL_DH_anon_WITH_RC4_128_MD5",
			"SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
			"SSL_DH_anon_WITH_DES_CBC_SHA",
			"SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",
			"SSL_FORTEZZA_KEA_WITH_NULL_SHA",
			"SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA",
			"SSL_FORTEZZA_KEA_WITH_RC4_128_SHA");
	public static final String URLPARAM_SAMLREQUEST_REDIRECT = "SAMLRequest";
	public static final String URLPARAM_SAMLREQUEST_POST= "SAMLRequest";
	public static final String URLPARAM_SAMLRESPONSE_REDIRECT= "SAMLResponse";
	public static final String URLPARAM_SAMLRESPONSE_POST= "SAMLResponse";
	public static final String URLPARAM_SAMLARTIFACT = "SAMLArt";
	public static final String URLPARAM_RELAYSTATE = "RelayState";
	public static final String LANG_ENGLISH = "en";
	public static final String USE_ENCRYPTION = "encryption";
	public static final String USE_SIGNING = "signing";
	public static final String NAMESPACE_ATTR_X500 = "urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500";
	public static final String X500_ENCODING = "Encoding";
	public static final String X500_ENCODING_LDAP = "LDAP";
	public static final String URLPARAM_SIGNATURE = "Signature";
	public static final String URLPARAM_SAMLENCODING = "SAMLEncoding";
	public static final Object SAMLENCODING_DEFLATE = "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE";
	public static final String HEADER_CACHECONTROL = "Cache-Control";
	public static final String HEADER_CACHECONTROL_VALUE = "no-cache, no-store";
	public static final String HEADER_PRAGMA = "Pragma";
	public static final String HEADER_PRAGMA_VALUE = "no-cache";
}
