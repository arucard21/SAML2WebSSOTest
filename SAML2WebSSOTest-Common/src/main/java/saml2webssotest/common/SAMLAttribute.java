package saml2webssotest.common;

import java.util.ArrayList;

/**
 * The Attribute class contains the values pertaining to a single attribute in the saml namespace
 */
public class SAMLAttribute {

	private String namespace;
	private String prefix;
	private String attributeName;
	private String nameFormat;
	private String friendlyName;
	private String attributeValue;
	private ArrayList<StringPair> customAttributes = new ArrayList<StringPair>();
	
	public SAMLAttribute(String namespace, String prefix, String attributeName, String nameFormat, String friendlyName, String attributeValue){
		this.namespace = namespace;
		this.prefix = prefix;
		this.attributeName = attributeName;
		this.nameFormat = nameFormat;
		this.friendlyName = friendlyName;
		this.attributeValue = attributeValue;
	}
	
	public String getNamespace() {
		return namespace;
	}
	
	public String getPrefix(){
		return prefix;
	}

	public String getAttributeName() {
		return attributeName;
	}

	public String getNameFormat() {
		return nameFormat;
	}

	public String getFriendlyName() {
		return friendlyName;
	}

	public String getAttributeValue() {
		return attributeValue;
	}

	/**
	 * @return the customAttributes
	 */
	public ArrayList<StringPair> getCustomAttributes() {
		return customAttributes;
	}

	/**
	 * @param customAttributes the customAttributes to set
	 */
	public void setCustomAttributes(ArrayList<StringPair> customAttributes) {
		this.customAttributes = customAttributes;
	}
	
	/**
	 * Add a custom attribute to this Attribute. 
	 * Note that this is a regular XML attribute for the XML node that is 
	 * called Attribute. (e.g. <Attribute attrName="attrValue">)
	 * 
	 * @param attrName
	 * @param attrValue
	 */
	/*public void addCustomAttribute(String attrName, String attrValue){
		customAttributes.put(attrName, attrValue);
	}
	
	public HashMap<String, String> getCustomAttributes(){
		return customAttributes;
	}*/
}