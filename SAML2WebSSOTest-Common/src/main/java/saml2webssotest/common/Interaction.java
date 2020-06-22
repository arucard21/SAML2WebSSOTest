package saml2webssotest.common;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

/**
 * This class contains all the information required to interact with a link (anchor) on an HTML page.
 * 
 * The lookupAttribute can be "id" or "name".
 * 
 * @author RiaasM
 *
 */
public class Interaction {

	private static final Logger logger = LoggerFactory.getLogger(Interaction.class);
	
	private String lookupAttribute;
	private String lookupValue;
	
	/**
	 * Create a new ElementInteraction
	 * 
	 * @param attribute is the type of lookup that is required for this interaction (value should be id or name)
	 * @param value is the string which should be used for the lookup. Its value depends on the type of lookup performed.
	 */
	public Interaction(String attribute, String value){
		setLookupAttribute(attribute);
		setLookupValue(value);
	}

	/**
	 * @return the lookupType
	 */
	public String getLookupAttribute() {
		return lookupAttribute;
	}

	/**
	 * @param lookupType the lookupType to set
	 */
	public void setLookupAttribute(String lookupType) {
		this.lookupAttribute = lookupType;
	}

	/**
	 * @return the lookupValue
	 */
	public String getLookupValue() {
		return lookupValue;
	}

	/**
	 * @param lookupValue the lookupValue to set
	 */
	public void setLookupValue(String lookupValue) {
		this.lookupValue = lookupValue;
	}
	
	/**
	 * Execute the interaction defined by this class on the given HTML page
	 * 
	 * @param interactionPage is the HTML page with which we should interact
	 * @return the HTML page that is returned after interacting with the given HTML page
	 */
	public HtmlPage executeOnPage(HtmlPage interactionPage){
		String inputValue = getLookupValue();
		HtmlElement targetElement;
		if (getLookupAttribute().equalsIgnoreCase("id"))
			targetElement = interactionPage.getHtmlElementById(inputValue);
		else if (getLookupAttribute().equalsIgnoreCase("name"))
			targetElement = interactionPage.getElementByName(inputValue);
		else{
			logger.error("Unknown lookup attribute found in interaction object");
			targetElement = null;
		}
		if (targetElement != null){
			try {
				// click the link and return the retrieved page
				return targetElement.click();
			} catch (IOException ioe) {
				logger.error("IOException occurred while executing the requested interaction", ioe);
			}
		}
		return null;
	}
}
