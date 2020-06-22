package saml2webssotest.common;

import java.net.URL;
import java.util.List;

import org.opensaml.xml.security.x509.X509Credential;
import org.w3c.dom.Document;

/**
 * This is the module containing the base interfaces for every test suite. This is extended by the IdP and SP test suites which in 
 * turn can be extended to create custom test suites to test either an IdP or an SP.
 * 
 * @author: Riaas Mokiem
 */
public interface TestSuite {
	/**
	 * Get the metadata that should be used in the mocked SAML entity for this test suite.
	 * 
	 * This allows you to use specific IdP or SP metadata for the mocked SAML entity in each test suite, which
	 * is defined in this method. 
	 * 
	 * @return: the metadata XML that should be used by the mocked SAML entity when running tests from this test suite
	 */
	public String getMockedMetadata();
	
	/**
	 * Retrieves the URL for the mock server
	 * 
	 * @return the URL for the mock server
	 */
	public URL getMockServerURL();
	
	/**
	 * Retrieve the X.509 Certificate that should be used by the mock server.
	 * 
	 * @param certLocation contains the location of the certificate file that should be used (e.g. "keys/mycert.pem")
	 * 			Can be null or empty, in which case a default certificate is used
	 * @return: the X.509 Certificate credentials
	 */
	public X509Credential getX509Credentials(String certLocation);
	
	/**
	 * Retrieve a list of test suites that this test suite depends on.
	 * These test suites will be run before this test suite is run. This allows
	 * you to run all test cases in a test suite as well as all test suites that
	 * test specifications that your depend on.
	 * 
	 * Note that this is ignored when run a single test case from a test suite. 
	 * 
	 * @return the list of depending test suites
	 */
	public List<TestSuite> getDependencies();

	/**
	 * The interface for all test cases. Defines the methods that are required for the test runner to correctly run
	 * the test case.
	 * 
	 * You can extend this TestCase to create specific types of test cases, as is done to create the MetadataTestCase. You 
	 * can then implement these specific types of test cases in order to specify a test case.
	 * 
	 * @author RiaasM
	 *
	 */
	public interface TestCase{

		/**
		 * Retrieve a description of the test case
		 * 
		 * @return a description of this test case
		 */
		String getDescription();
		
		/**
		 * Retrieve a more descriptive, human-readable message about the test result.
		 * This can also contain information about how and why the result was achieved.
		 * 
		 * @return the message about the test result
		 */
		String getResultMessage();
		
		/**
		 * Specify if the requirement on which this test case is based, is mandatory.
		 *  
		 * This would correspond with all MUST requirements from the SAML specifications.
		 *  
		 * @return true if the SAML entity MUST conform to the requirement in order to be valid
		 */
		boolean isMandatory();
	}
	
	/**
	 * The interface for a test case that is intended to test the XML metadata
	 * of a SAML entity. 
	 * 
	 * @author RiaasM
	 *
	 */
	public interface MetadataTestCase extends TestCase {
		
		/**
		 * Check the provided metadata.  
		 * 
		 * @return the status of the test
		 */
		boolean checkMetadata(Document metadata);
	}
}