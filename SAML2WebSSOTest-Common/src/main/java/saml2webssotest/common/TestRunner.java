package saml2webssotest.common;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.net.InetSocketAddress;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;

import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.opensaml.xml.security.x509.X509Credential;
import org.reflections.Reflections;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import saml2webssotest.common.TestSuite.TestCase;

import com.gargoylesoftware.htmlunit.ElementNotFoundException;
import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.Page;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.google.gson.GsonBuilder;

public abstract class TestRunner {
	/**
	 * Logger for this class
	 */
	private final Logger logger = LoggerFactory.getLogger(TestRunner.class);
	/**
	 * Setting to determine if depending test suites should be run
	 */
	public boolean recursive;
	/**
	 * Setting to determine if embedded tests should be added to the test results
	 */
	public boolean showEmbedded;
	/**
	 * The test suite that is being run
	 */
	public TestSuite testsuite;
	/**
	 * A list of names of the test suites that are currently being run.
	 * This is used to keep track of which test suites have already been run so
	 * we can avoid re-running the same test suite
	 */
	public ArrayList<String> currentTestSuites = new ArrayList<String>();
	/**
	 * The name of the test case that should be run
	 */
	public String testcaseName;
	/**
	 * The list of test results for each test suite that is run
	 */
	HashMap<String, List<TestResult>> testResults = new HashMap<String, List<TestResult>>();
	/**
	 * Contains the mock server
	 */
	public Server mockServer;
	/**
	 * Display the list of test suites
	 */
	public void listTestSuites(String tsPackage) {
		Reflections tsReflections = new Reflections(tsPackage);
		Set<Class<? extends TestSuite>> testsuites = tsReflections.getSubTypesOf(TestSuite.class);
		for (Class<? extends TestSuite> ts : testsuites){
			// only print concrete classes
			if(!Modifier.isAbstract(ts.getModifiers()) && !Modifier.isInterface(ts.getModifiers())){
				System.out.println(ts.getSimpleName());
			}
		}
	}

	/**
	 * Display the list of test cases for the current test suite
	 */
	public void listTestCases(TestSuite ts) {
		// iterate through all test cases
		for (Class<?> testcase : ts.getClass().getDeclaredClasses()) {
			// check if the class object is in fact a test case
			if (TestCase.class.isAssignableFrom(testcase)) {
				// output the name of the test case
				System.out.println(testcase.getSimpleName());
				TestCase tc;
				try {
					tc = (TestCase) testcase.getConstructor(ts.getClass()).newInstance(ts);
					// also output the description of the test case
					System.out.println("\t" + tc.getDescription());
				} catch (InstantiationException e) {
					logger.error("Could not create a new instance of the test case", e);
				} catch (IllegalAccessException e) {
					logger.error("Could not create a new instance of the test case", e);
				} catch (IllegalArgumentException e) {
					logger.error("Could not create a new instance of the test case", e);
				} catch (InvocationTargetException e) {
					logger.error("Could not create a new instance of the test case", e);
				} catch (NoSuchMethodException e) {
					logger.error("Could not retrieve the constructor of the test case class", e);
				} catch (SecurityException e) {
					logger.error("Could not retrieve the constructor of the test case class", e);
				}
				System.out.println("");
			} else {
				logger.error("Class was not a test case");
			}
		}
	}

	/**
	 * Display the mock IdP's metadata for the provided test suite.
	 * 
	 * @param ts
	 *            is the test suite for which we should display the metadata
	 */
	public void outputMockedMetadata(TestSuite ts) {
		System.out.println(ts.getMockedMetadata());
	}

	public X509Credential getMockedX509Credentials(String certLocation){
		return testsuite.getX509Credentials(certLocation);
	}
	/**
	 * Process the test results and output them as JSON
	 * 
	 * @param testresults is a list of test case results
	 */
	public void outputTestResults() {
		// sort the test results
		TreeMap<String, List<TestResult>> sortedResults = new TreeMap<String, List<TestResult>>(testResults);
		System.out.println(new GsonBuilder().setPrettyPrinting().create().toJson(sortedResults));
	}

	/**
	 * Create a new mock server for the given test suite with the provided handler.
	 * Additional handles can be added to the returned Server object, if needed.
	 * 
	 * @param mockserverURL is the URL on which the mock server will be used
	 * @param handler is the handler that will be used in the given test suite
	 * @return the created mock server
	 */
	public Server newMockServer(URL mockServerURL, Handler handler) {
		// create the mock IdP and add all required handlers
		mockServer = new Server(
				new InetSocketAddress(mockServerURL.getHost(), mockServerURL.getPort()));
		
		// add a context handler to properly handle the sso path
		ContextHandler context = new ContextHandler();
		context.setContextPath(mockServerURL.getPath());
		mockServer.setHandler(context);

		// add the SAML Request handler to the mock IdP
		mockServer.setHandler(handler);
		
		return mockServer;
	}

	/**
	 * Retrieve the test case from the test suite that matches the given test case name, or 
	 * all test cases if the given test case name is empty or null. 
	 * 
	 * @param ts is the test suite in which the test cases are located
	 * @param tn is the name of the test case that should be returned. If empty, all 
	 * test cases in the test suite will be returned
	 * @return a list containing either the test case from the given test suite that matches 
	 * the given test case name, or all test cases in the test suite if the given test case 
	 * name is null or empty
	 */
	public ArrayList<TestCase> getTestCases(TestSuite ts, String tn) {
		ArrayList<TestCase> testcases = new ArrayList<TestCase>();
		for (Class<?> testcaseClass : ts.getClass().getDeclaredClasses()) {
			TestCase curTestcase;
			try {
				curTestcase = (TestCase) testcaseClass.getConstructor(ts.getClass()).newInstance(ts);
				// add the test case to the list if it matches the name that was provided, or if no name was provided
				if (tn == null || tn.isEmpty() || tn.equals(testcaseClass.getSimpleName())) {
					testcases.add(curTestcase);
				}
			} catch (InstantiationException e) {
				logger.error("Could not instantiate an instance of the test suite or case", e);
			} catch (IllegalAccessException e) {
				logger.error("Could not access the test suite class or test case class", e);
			} catch (IllegalArgumentException e) {
				logger.error("Could not create a new instance of the test case", e);
			} catch (InvocationTargetException e) {
				logger.error("Could not create a new instance of the test case", e);
			} catch (NoSuchMethodException e) {
				logger.error("Could not retrieve the constructor of the test case class", e);
			} catch (SecurityException e) {
				logger.error("Could not retrieve the constructor of the test case class", e);
			} 
		}
		return testcases;
	}

	/**
	 * Retrieves a page at the given URL in the given webclient and performs the given interactions
	 * on that page.
	 * If no URL is given, only the interactions are performed in the given browser
	 * 
	 * @param interactionPage is the page with which we we wish to interact
	 * @param interactions is a list of interactions that should be performed on the retrieved page
	 * @return the page as it was retrieved after all interactions are completed
	 */
	@SuppressWarnings("unchecked")
	public <P extends Page> P interactWithPage(Page interactionPage, List<Interaction> interactions) {
		HtmlPage returnPage = null;
		// start login attempt with target SP
		try {
			// execute all interactions
			for(Interaction interaction : interactions){
				if(interactionPage instanceof HtmlPage){
					// cast the Page to an HtmlPage so we can interact with it
					HtmlPage loginPage = (HtmlPage) interactionPage;
					logger.trace("Login page");
					logger.trace(loginPage.getWebResponse().getContentAsString());
				
					// cast the interaction to the correct class
					if(interaction instanceof FormInteraction) {
						FormInteraction formInteraction = (FormInteraction) interaction;
						returnPage = formInteraction.executeOnPage(loginPage);
						
					    logger.trace("Login page (after form submit)");
					    logger.trace(loginPage.getWebResponse().getContentAsString());
					}
					else if(interaction instanceof LinkInteraction) {
						LinkInteraction linkInteraction = (LinkInteraction) interaction;
						returnPage = linkInteraction.executeOnPage(loginPage);
						
						logger.trace("Login page (after link click)");
					    logger.trace(interactionPage.getWebResponse().getContentAsString());
					}
					else {
						returnPage = interaction.executeOnPage(loginPage);
						
						logger.trace("Login page (after element click)");
					    logger.trace(interactionPage.getWebResponse().getContentAsString());
					}
				}
				else{
					logger.error("The login page is not an HTML page, so it's not possible to interact with it");
					logger.trace("Retrieved page:");
					logger.trace(interactionPage.getWebResponse().getContentAsString());
					break;
				}
			}
			// return the retrieved page
			return (P) returnPage;
		} catch (FailingHttpStatusCodeException e) {
			logger.error("The login page did not return a valid HTTP status code");
		} catch (ElementNotFoundException e){
			logger.error("The interaction link lookup could not find the specified element");
		}
		return null;
	}

	/**
	 * Retrieve the TestSuite object that was used to initiate the test runner
	 * 
	 * @return the TestSuite object used to initiate the test runner
	 */
	public TestSuite getMainTestSuite(){
		return testsuite;
	}
	
	/**
	 * Run the requested testcase(s) from the requested test suite.
	 * 
	 * Prints the results in JSON format to System.out
	 * 
	 * @param ts is the Test Suite object from which we will run test cases
	 */
	public void runTestSuite(TestSuite ts){
		String tsName = ts.getClass().getSimpleName();
		// run any depending test suite only if the entire test suite is being run and recursion was allowed
		if ( recursive && (testcaseName == null || testcaseName.isEmpty())){
			// add the current test suite to the list of suites that are being run
			currentTestSuites.add(tsName);
			List<TestSuite> depends = ts.getDependencies();
			// run each depending test suite
			for (TestSuite depend: depends ){
				// only run the test suite if it is not already being run
				if (!currentTestSuites.contains(depend.getClass().getSimpleName())){
					runTestSuite(depend);
				}
			}
		}
		
		// load the test cases from this test suite that we wish to run
		ArrayList<TestCase> testcases = getTestCases(ts, testcaseName);
		// run the test case(s) from the test suite
		ArrayList<TestResult> testsuiteResults =  new ArrayList<TestResult>();
		for (TestCase testcase : testcases) {
			boolean status;
			String resultMessage;
			try {
				// initialize a new mock server for use in the test case
				initMockServer();
				// run the test case
				status = runTest(testcase);
				// get the result message
				resultMessage = testcase.getResultMessage();
			} catch (Exception e) {
				// make sure any exceptions thrown while running a test are caught here
				// so they don't cause all other tests to be cancelled
				logger.error("An exception occurred while running test case: " + testcase.getClass().getSimpleName(), e);
				status = false;
				resultMessage = "The following exception has occurred (See the log for the full stacktrace): " + e.toString();
			} finally{
				// kill the mock server if it is still running
				killMockServer();
			}
	
			// add this test result to the list of test results
			testsuiteResults.add(
					new TestResult(testcase.getClass().getSimpleName())
					.withDescription(testcase.getDescription())
					.isMandatory(testcase.isMandatory())
					.withResultStatus(status)
					.withResultMessage(resultMessage));
		}
		// retrieve the list of existing test results for this test suite
		List<TestResult> curTsResults = testResults.get(tsName);
		// if existing test results were found, add them to the existing ones
		if (curTsResults != null){
			testsuiteResults.addAll(curTsResults);
		}
		// add test results, if any are available
		if(!testsuiteResults.isEmpty()){
			// add the test results of this suite to all test results
			testResults.put(tsName, testsuiteResults);
		}
	}
	
	/**
	 * Add a single, test result to the list of test results that will
	 * be displayed to the user. The test result must be added as part
	 * of a specific test suite. This is only used for adding test results
	 * for the the embedded tests that are performed within the test
	 * framework
	 * 
	 * @param tsName is the name of the test suite that the test results belongs to
	 * @param tcResult is the test result that should be added to the list for the given test suite
	 */
	public void addTestResult(String tsName, TestResult tcResult){
		if(showEmbedded){
			// retrieve the list of existing test results for this test suite
			List<TestResult> curTsResults = testResults.get(tsName);
			// if no existing test results were found, initialize the list
			if (curTsResults == null){
				curTsResults = new ArrayList<TestResult>();
			}
			// only add the new test results if one with the same name and result doesn't already exist
			if(!curTsResults.contains(tcResult)){
				// add the new test result to the list of test results 
				curTsResults.add(tcResult);				
				// store the new list of test results 
				testResults.put(tsName, curTsResults);
			}
		}
	}

	public abstract void initMockServer();
	
	public abstract void killMockServer();

	public abstract boolean runTest(TestCase testcase);

	public abstract void loadConfig(String optionValue); 
}
