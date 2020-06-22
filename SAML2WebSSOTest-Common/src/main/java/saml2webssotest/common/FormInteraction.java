package saml2webssotest.common;

import java.io.IOException;
import java.util.ArrayList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlSubmitInput;

/**
 * This class contains all information required to interact with a form on an HTML page.
 * 
 * The lookupAttribute can be "id" or "name".
 * 
 * @author RiaasM
 *
 */
public class FormInteraction extends Interaction {
	
	private static final Logger logger = LoggerFactory.getLogger(FormInteraction.class);
	
	private String submitName;
	private ArrayList<StringPair> inputs = new ArrayList<StringPair>();
	
	public FormInteraction(String attribute, String value) {
		super(attribute, value);
	}

	/**
	 * @return the submitName
	 */
	public String getSubmitName() {
		return submitName;
	}

	/**
	 * @param submitName the submitName to set
	 */
	public void setSubmitName(String submitName) {
		this.submitName = submitName;
	}

	/**
	 * @return the inputs
	 */
	public ArrayList<StringPair> getInputs() {
		return inputs;
	}
	
	/**
	 * 	 * 
	 * @param inputs
	 */
	public void setInputs(ArrayList<StringPair> inputs) {
		this.inputs = inputs;
	}

	/**
	 * Execute the interaction defined by this class on the given HTML page
	 * 
	 * @param interactionPage is the HTML page with which we should interact
	 * @return the HTML page that is returned after interacting with the given HTML page
	 */
	public HtmlPage executeOnPage(HtmlPage interactionPage){
		HtmlForm pageForm = null;
		if (getLookupAttribute().equalsIgnoreCase("id")){
			HtmlElement targetElement = interactionPage.getHtmlElementById(getLookupValue());
			if (targetElement instanceof HtmlForm)
				pageForm = (HtmlForm) targetElement;
		}
		else if (getLookupAttribute().equalsIgnoreCase("name")){
			pageForm = interactionPage.getFormByName(getLookupValue());
		}
		else{
			logger.error("Unknown lookup attribute found in form interaction object");
		}
		
		// make sure you have a form element before continuing
		if (pageForm == null){
			logger.error("Could not retrieve the form element");
			return null;
		}
		
		HtmlSubmitInput button = pageForm.getInputByName(getSubmitName());
		
		// fill in all provided input fields
		ArrayList<StringPair> inputs = getInputs();
		for(StringPair input : inputs){
			// retrieve the first input field with the provided name
			HtmlInput textField = pageForm.getInputsByName(input.getName()).get(0);	
			textField.setValueAttribute(input.getValue());
		}
	    // submit the form, updating the retrieved page
		if (button != null){
			try {
				// click the link and return the retrieved page
				return button.click();
			} catch (IOException ioe) {
				logger.error("IOException occurred while executing the requested interaction", ioe);
			}
		}
		return null;
	}
}
