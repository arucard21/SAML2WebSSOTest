package saml2webssotest.common;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

/**
 * This class contains all the information required to interact with a link (anchor) on an HTML page.
 * 
 * The lookupAttribute can be "id", "name", "href" or "text".
 * 
 * @author RiaasM
 *
 */
public class LinkInteraction  extends Interaction{
	
	private static final Logger logger = LoggerFactory.getLogger(LinkInteraction.class);
	
	public LinkInteraction(String attribute, String value) {
		super(attribute, value);
	}

	/**
	 * Execute the interaction defined by this class on the given HTML page
	 * 
	 * @param interactionPage is the HTML page with which we should interact
	 * @return the HTML page that is returned after interacting with the given HTML page
	 */
	public HtmlPage executeOnPage(HtmlPage interactionPage){
		HtmlAnchor targetAnchor = null;
		if (getLookupAttribute().equalsIgnoreCase("id")){
			HtmlElement targetElement = interactionPage.getHtmlElementById(getLookupValue());
			if (targetElement instanceof HtmlAnchor)
				targetAnchor = (HtmlAnchor) targetElement;
		}
		else if (getLookupAttribute().equalsIgnoreCase("name"))
			targetAnchor = interactionPage.getAnchorByName(getLookupValue());
		else if (getLookupAttribute().equalsIgnoreCase("href"))
			targetAnchor = interactionPage.getAnchorByHref(getLookupValue());
		else if (getLookupAttribute().equalsIgnoreCase("text"))
			targetAnchor = interactionPage.getAnchorByText(getLookupValue());
		else{
			logger.error("Unknown lookup attribute found in link interaction object");
		}
		if (targetAnchor != null){
			try {
				// click the link and return the retrieved page
				return targetAnchor.click();
			} catch (IOException ioe) {
				logger.error("IOException occurred while executing the requested interaction", ioe);
			}
		}
		else{
			logger.error("Could not retrieve link element");
		}
		return null;
	}
}
