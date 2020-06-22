package saml2webssotest.common;

import java.lang.reflect.Type;

import org.w3c.dom.Document;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;

public class MetadataDeserializer implements JsonDeserializer<Document> {

	@Override
	public Document deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
		return SAMLUtil.fromXML(json.getAsString());
	}

}
