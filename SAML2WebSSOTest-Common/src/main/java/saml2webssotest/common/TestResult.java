package saml2webssotest.common;

/**
 * TestResult is a simple container class for the result of a single test case
 * 
 * @author RiaasM
 *
 */
public class TestResult {
	String name;
	String description = "";
	boolean mandatory = false;
	String result = "";
	String resultMessage = "";

	/**
	 * Construct the minimal TestResult object 
	 * 
	 * @param name is the name of the test for which this result is created
	 */
	public TestResult(String nm) {
		this.name = nm;
	}

	public boolean getResult() {
		if (result.equals("PASS")){
			return true;
		}
		return false;
	}
	
	public String getName() {
		return name;
	}

	public String getDescription() {
		return description;
	}

	public TestResult withDescription(String descr) {
		this.description = descr;
		return this;
	}

	public boolean getMandatory() {
		return mandatory;
	}

	public TestResult isMandatory(boolean mand) {
		this.mandatory = mand;
		return this;
	}

	public TestResult withResultStatus(boolean resultBool){
		if(resultBool)
			this.result = "PASS";
		else
			this.result = "FAIL";
		return this;
	}

	public String getResultMessage() {
		return resultMessage;
	}
	
	public TestResult withResultMessage(String resMsg){
		this.resultMessage = resMsg;
		return this;
	}

	@Override
	public boolean equals(Object other){
		if(other == null){
			return false;
		}
		if(!(other instanceof TestResult)){
			return false;
		}
		TestResult otherTC = (TestResult) other;
		return getResult() == otherTC.getResult() &&
				getResultMessage().equalsIgnoreCase(otherTC.getResultMessage()) &&
				getName().equalsIgnoreCase(otherTC.getName()) &&
				getDescription().equalsIgnoreCase(otherTC.getDescription()) &&
				getMandatory() ==  otherTC.getMandatory();
	}

	@Override
	public int hashCode() {
		// return non-negative hashcode
		return Math.abs(new Boolean(getResult()).hashCode()+getResultMessage().hashCode()+getName().hashCode()+getDescription().hashCode()+new Boolean(getMandatory()).hashCode());
	}
}
