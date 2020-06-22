package saml2webssotest.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.codec.binary.StringUtils;
import org.opensaml.xml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

/**
 * Utility class containing some convenience methods. 
 * 
 * The encode/decode methods are based on (basically copied from) the corresponding methods in OpenSAML. Unfortunately, those 
 * methods were not easily accessible so these methods can be used instead. They still use the Base64 implementation from OpenSAML.
 * @author RiaasM
 *
 */
public class SAMLUtil {
	
	private static final Logger logger = LoggerFactory.getLogger(SAMLUtil.class);
	
	/**
	 * Encodes the SAML Request or Response according to the Redirect binding.
	 * 
	 * @param message is the original SAML message as a string
	 * @return the encoded SAML message
	 */
	public static String encodeSamlMessageForRedirect(String message){
		try {
			ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            DeflaterOutputStream deflaterStream = new DeflaterOutputStream(bytesOut, deflater);
            deflaterStream.write(message.getBytes("UTF-8"));
            deflaterStream.finish();

			String b64compressedRequest = Base64.encodeBytes(bytesOut.toByteArray(), Base64.DONT_BREAK_LINES);
			// url-encode
			return URLEncoder.encode(b64compressedRequest, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			logger.error("Could not deflate or url-encode the message", e);
		} catch (IOException e) {
			logger.error("Could not deflate the message", e);
		}
		return null;
	}
	
	/**
	 * Encodes the SAML Request or Response according to the POST binding.
	 * 
	 * @param message is the original SAML message as a string
	 * @return the encoded SAML message
	 */
	public static String encodeSamlMessageForPost(String message) {
		return Base64.encodeBytes(StringUtils.getBytesUtf8(message));
	}

	/**
	 * Decodes the SAML Request or Response according to the Redirect binding.
	 * 
	 * Note that it does not perform the URL-decoding since this is often already done
	 * automatically. Make sure the provided string is already URL-decoded.
	 * 
	 * @param request is the encoded SAML message as a string
	 * @return the decoded SAML message
	 */
	public static String decodeSamlMessageForRedirect(String request) {
		try{
			// url-decoding was already done by the mock IdP so only do base64-decode and decompress
			ByteArrayInputStream bytesIn = new ByteArrayInputStream(Base64.decode(request));
            InflaterInputStream inflater = new InflaterInputStream(bytesIn, new Inflater(true));
            ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
            // read the decompressed data and write it to a string
            byte[] buffer = new byte[1024];
            int length = 0;
            while ((length = inflater.read(buffer)) >= 0) {
                bytesOut.write(buffer, 0, length);
            }
            return bytesOut.toString();
		} catch (IOException e) {
			logger.error("Could not inflate the message", e);
		}
		return null;
	}

	/**
	 * Decodes the SAML Request according to the binding.
	 * 
	 * Note that a SAML Request can only be used with the Redirect and POST bindings
	 * 
	 * @param request is the encoded SAML Request as a string
	 * @param binding is the binding for which it should be decoded
	 * @return the decoded SAML Request
	 */
	public static String decodeSamlMessageForPost(String request) {
		// base64-decode
		return StringUtils.newStringUtf8(Base64.decode(request));
	}
	
	/**
	 * Convert an XML string (or URL to an XML document) to an org.w3c.dom.Document object
	 * 
	 * @param xmlString is the XML document you wish to convert, either as XML directly in
	 * the string or the location (in URL form) of the XML document
	 * @return the Document object representing the provided XML document 
	 */
	public static Document fromXML(String xmlString){
		logger.debug("Creating org.w3c.dom.Document from XML String");

		if (xmlString != null && !xmlString.isEmpty()){
			try {
				DocumentBuilderFactory xmlDocBuilder = DocumentBuilderFactory.newInstance();
				xmlDocBuilder.setNamespaceAware(true);
				DocumentBuilder docbuilder = xmlDocBuilder.newDocumentBuilder();
				// check if the string contains a URL and retrieve the XML from there
				// otherwise just treat the string itself as XML 
				try{
					URL xmlLocation = new URL(xmlString);
					return docbuilder.parse(xmlLocation.toExternalForm());
				} catch(MalformedURLException noURL){
					return docbuilder.parse(new InputSource(new StringReader(xmlString)));
				}
			} catch (ParserConfigurationException e) {
				logger.error("Could not parse the string as Document", e);
			} catch (SAXException e) {
				logger.error("Could not parse the string as Document", e);
			} catch (IOException e) {
				logger.error("Could not parse the string as Document", e);
			}
		}
		return null;
	}
	
	/**
	 * Convert an XML String (or URL to an XML document) to an XMLObject object
	 * 
	 * The returned XMLObject can be cast to the appropriate SAML class (e.g. Response
	 * or AuthnRequest).
	 * 
	 * @param samlXML is the XML document you wish to convert, either as XML directly in
	 * the string or the location (in URL form) of the XML document
	 * @return the XMLObject object representing the provided XML document
	 */
	public static XMLObject XMLObjectFromXML(String samlXML){
		Element samlElem = fromXML(samlXML).getDocumentElement();
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(samlElem);
		try {
			return unmarshaller.unmarshall(samlElem);
		} catch (UnmarshallingException e) {
			logger.error("Could not create SAML Object from XML string", e);
		}
		return null;
	}
	
	/**
	 * Convert a SAML Object to XML in a string
	 * 
	 * @param samlObj is the SAML object that should be converted
	 * @return the given SAML object as a string or an empty string if it could not be converted
	 */
	public static String toXML(XMLObject samlObj){
		try {
			logger.debug("Creating XML String from SAML Object");
			
			Marshaller marshall = Configuration.getMarshallerFactory().getMarshaller(samlObj.getElementQName());
			// Marshall the SAML object into an XML object
			Document xmlDoc = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
			marshall.marshall(samlObj, xmlDoc);
			return toXML(xmlDoc);
		} catch (MarshallingException e) {
			logger.error("Could not parse the Document", e);
		} catch (ParserConfigurationException e) {
			logger.error("Could not parse the Document", e);
		}
		return "";
	}
	
	/**
	 * Convert an org.w3c.dom.Document to XML in a string
	 * 
	 * @param doc is the Document that should be converted
	 * @return the given XML Document as a string or an empty string if it could not be converted
	 */
	public static String toXML(Document doc){
		logger.debug("Creating XML String from org.w3c.dom.Document");
		try {
			// Convert the XML object to a string
			Transformer transformer = TransformerFactory.newInstance().newTransformer();
			StringWriter writer = new StringWriter();
			transformer.transform(new DOMSource(doc), new StreamResult(writer));
			return writer.toString();
		} catch (TransformerConfigurationException e) {
			logger.error("Could not convert the XML object to a string", e);
		} catch (TransformerFactoryConfigurationError e) {
			logger.error("Could not convert the XML object to a string", e);
		} catch (TransformerException e) {
			logger.error("Could not convert the XML object to a string", e);
		}
		return "";
	}
	
	/**
	 * Sign a SAML object with the given private key and certificate
	 * 
	 * @param samlObj is the object that should be signed
	 * @param credential is the object that holds the X509 certificate and private key that should be used for signing
	 * @return the signed SAML object, or the original SAML object if signing failed
	 */
	public static void sign(SignableSAMLObject samlObj, X509Credential credential){
		try {
			DefaultBootstrap.bootstrap();
			XMLObjectBuilderFactory builderfac = Configuration.getBuilderFactory();
			Signature signature = (Signature) builderfac.getBuilder(Signature.DEFAULT_ELEMENT_NAME).buildObject(Signature.DEFAULT_ELEMENT_NAME);
			
			signature.setSigningCredential(credential);
			signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
			
			SecurityConfiguration secConfiguration = Configuration.getGlobalSecurityConfiguration();
			NamedKeyInfoGeneratorManager namedKeyInfoGeneratorManager = secConfiguration.getKeyInfoGeneratorManager();
			KeyInfoGeneratorManager keyInfoGeneratorManager = namedKeyInfoGeneratorManager.getDefaultManager();
			KeyInfoGeneratorFactory keyInfoGeneratorFactory = keyInfoGeneratorManager.getFactory(credential);
			KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();
			KeyInfo keyInfo = keyInfoGenerator.generate(credential);
			signature.setKeyInfo(keyInfo);
			// add signature to the SAML object
			samlObj.setSignature(signature);
			// marshall the SAML object in preparation of signing
			Configuration.getMarshallerFactory().getMarshaller(samlObj).marshall(samlObj);
			// actually calculate the signature
			Signer.signObject(signature);
		} catch (ConfigurationException e) {
			logger.error("Could not sign the message", e);
		} catch (MarshallingException e) {
			logger.error("Could not sign the message", e);
		} catch (SignatureException e) {
			logger.error("Could not sign the message", e);
		} catch (SecurityException e) {
			logger.error("Could not sign the message", e);
		}
	}

	/**
	 * Retrieve the ID of the top-level node in the provided XML
	 * 
	 * @param message is the XML message from which we want the ID
	 * @return the value of the ID attribute of the top-level Node in the XML
	 */
	public static String getSamlMessageID(String message) {
		Document requestDoc = SAMLUtil.fromXML(message);
		Node reqID = requestDoc.getDocumentElement().getAttributes().getNamedItem("ID");
		return reqID.getNodeValue();
	}
}
