package com.protect7.authanalyzer.util;

import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import com.protect7.authanalyzer.entities.AutoExtractLocation;
import com.protect7.authanalyzer.entities.FromToExtractLocation;
import com.protect7.authanalyzer.entities.Token;
import com.protect7.authanalyzer.entities.TokenBuilder;
import com.protect7.authanalyzer.entities.TokenLocation;
import com.protect7.authanalyzer.montoya.HttpExchange;
import com.protect7.authanalyzer.montoya.MontoyaUtils;

import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public class ExtractionHelper {

	public static ResponseExtractionContext responseContext(HttpResponse responseInfo) {
		return new ResponseExtractionContext(responseInfo);
	}

	public static class ResponseExtractionContext {
		private final HttpResponse responseInfo;
		private byte[] responseBytes;
		private String fullResponseAsString;
		private String headerAsString;
		private String bodyAsString;

		private ResponseExtractionContext(HttpResponse responseInfo) {
			this.responseInfo = responseInfo;
		}

		public HttpResponse responseInfo() {
			return responseInfo;
		}

		public byte[] responseBytes() {
			if (responseBytes == null) {
				responseBytes = responseInfo.toByteArray().getBytes();
			}
			return responseBytes;
		}

		public int bodyOffset() {
			byte[] bytes = responseBytes();
			int bodyOffset = responseInfo.bodyOffset();
			if (bodyOffset < 0) {
				return 0;
			}
			if (bodyOffset > bytes.length) {
				return bytes.length;
			}
			return bodyOffset;
		}

		public int bodyLength() {
			return responseBytes().length - bodyOffset();
		}

		public String fullResponseAsString() {
			if (fullResponseAsString == null) {
				fullResponseAsString = new String(responseBytes());
			}
			return fullResponseAsString;
		}

		public String headerAsString() {
			if (headerAsString == null) {
				headerAsString = new String(responseBytes(), 0, bodyOffset());
			}
			return headerAsString;
		}

		public String bodyAsString() {
			if (bodyAsString == null) {
				byte[] bytes = responseBytes();
				int bodyOffset = bodyOffset();
				bodyAsString = new String(bytes, bodyOffset, bytes.length - bodyOffset);
			}
			return bodyAsString;
		}
	}

	public static boolean extractCurrentTokenValue(HttpResponse sessionResponseInfo, Token token) {
		return extractCurrentTokenValue(responseContext(sessionResponseInfo), token);
	}

	public static boolean extractCurrentTokenValue(ResponseExtractionContext sessionResponseContext, Token token) {
		HttpResponse sessionResponseInfo = sessionResponseContext.responseInfo();
		if(token.doAutoExtractAtLocation(AutoExtractLocation.COOKIE)) {
			for (Cookie cookie : sessionResponseInfo.cookies()) {
				if (cookie.name().equals(token.getExtractName())) {
					token.setValue(cookie.value());
					return true;
				}
			}
		}
		if (token.doAutoExtractAtLocation(AutoExtractLocation.HTML) && (MontoyaUtils.mimeName(sessionResponseInfo.statedMimeType()).equals("HTML")
				|| MontoyaUtils.mimeName(sessionResponseInfo.inferredMimeType()).equals("HTML"))) {
			try {
				String value = getTokenValueFromInputField(sessionResponseContext.bodyAsString(), token.getExtractName());
				if (value != null) {
					token.setValue(value);
					return true;
				}
			} catch (Exception e) {
				MontoyaUtils.logError("Can not parse HTML Response. Error Message: " + e.getMessage());
			}
		}
		if (token.doAutoExtractAtLocation(AutoExtractLocation.JSON) && (MontoyaUtils.mimeName(sessionResponseInfo.statedMimeType()).equals("JSON")
				|| MontoyaUtils.mimeName(sessionResponseInfo.inferredMimeType()).equals("JSON"))) {
			JsonElement jsonElement = getBodyAsJson(sessionResponseContext);
			if(jsonElement != null) {
				String value = getJsonTokenValue(jsonElement, token);
				if (value != null) {
					token.setValue(value);
					return true;
				}
			}
		}
		return false;
	}

	public static String getTokenValueFromInputField(String document, String name) {
		Document doc = Jsoup.parse(document);
		Elements csrfFields = doc.getElementsByAttributeValue("name", name);
		for(Element element : csrfFields) {
			String csrfValue = element.attr("value");
			if(csrfValue != null && !csrfValue.equals("")) {
				return csrfValue;
			}
			csrfValue = element.attr("content");
			if(csrfValue != null && !csrfValue.equals("")) {
				return csrfValue;
			}
		}
		return null;
	}

	public static boolean extractTokenWithFromToString(HttpResponse responseInfo, Token token) {
		return extractTokenWithFromToString(responseContext(responseInfo), token);
	}

	public static boolean extractTokenWithFromToString(ResponseExtractionContext responseContext, Token token) {
		HttpResponse responseInfo = responseContext.responseInfo();
		try {
			boolean doExtract = token.doFromToExtractAtLocation(FromToExtractLocation.ALL);
			for(FromToExtractLocation locationType : FromToExtractLocation.values()) {
				if(locationType != FromToExtractLocation.ALL && locationType != FromToExtractLocation.HEADER && locationType != FromToExtractLocation.BODY) {
					if (token.doFromToExtractAtLocation(locationType) && (MontoyaUtils.mimeName(responseInfo.statedMimeType()).toUpperCase().equals(locationType.toString())
							|| MontoyaUtils.mimeName(responseInfo.inferredMimeType()).toUpperCase().equals(locationType.toString()))) {
						doExtract = true;
						break;
					}
				}
			}
			//Do extract per default if stated and inferred MIME Type can not be evaluated (e.g. redirect response without body content)
			if(MontoyaUtils.mimeName(responseInfo.inferredMimeType()).equals("") && MontoyaUtils.mimeName(responseInfo.statedMimeType()).equals("")) {
				doExtract = true;
			}
			if(doExtract) {
				String responseAsString = null;
				if(token.doFromToExtractAtLocation(FromToExtractLocation.HEADER) && token.doFromToExtractAtLocation(FromToExtractLocation.BODY)) {
					responseAsString = responseContext.fullResponseAsString();
				}
				else if(token.doFromToExtractAtLocation(FromToExtractLocation.HEADER) && !token.doFromToExtractAtLocation(FromToExtractLocation.BODY)) {
					responseAsString = responseContext.headerAsString();
				}
				else if(!token.doFromToExtractAtLocation(FromToExtractLocation.HEADER) && token.doFromToExtractAtLocation(FromToExtractLocation.BODY)) {
					responseAsString = responseContext.bodyAsString();
				}
				if(responseAsString != null) {
					int beginIndex = responseAsString.indexOf(token.getGrepFromString());
					if (beginIndex != -1) {
						beginIndex = beginIndex + token.getGrepFromString().length();
						// Only single lines in extraction scope
						String lineWithValue = responseAsString.substring(beginIndex).split("\n")[0];
						String value = null;
						if (token.getGrepToString().equals("")) {
							value = lineWithValue;
						} else {
							if (lineWithValue.contains(token.getGrepToString())) {
								value = lineWithValue.substring(0, lineWithValue.indexOf(token.getGrepToString()));
							}
						}
						if (value != null) {
							token.setValue(value);
							return true;
						}
					}
				}
			}
		} catch (Exception e) {
			MontoyaUtils.logError("Can not extract from to value. Error Message: " + e.getMessage());
		}
		return false;
	}
	
	private static String getJsonTokenValue(JsonElement jsonElement, Token token) {
		if (jsonElement.isJsonObject()) {
			JsonObject jsonObject = jsonElement.getAsJsonObject();
			for (Map.Entry<String, JsonElement> entry : jsonObject.entrySet()) {
				if (entry.getValue().isJsonArray() || entry.getValue().isJsonObject()) {
					String value = getJsonTokenValue(entry.getValue(), token);
					if (value != null) {
						return value;
					}
				}
				if (entry.getValue().isJsonPrimitive()) {
					if (entry.getKey().equals(token.getExtractName())) {
						return entry.getValue().getAsString();
					}
				}
			}
		}
		if (jsonElement.isJsonArray()) {
			for (JsonElement arrayJsonEl : jsonElement.getAsJsonArray()) {
				if (arrayJsonEl.isJsonArray() || arrayJsonEl.isJsonObject()) {
					String value = getJsonTokenValue(arrayJsonEl, token);
					if (value != null) {
						return value;
					}
				}
			}
		}
		return null;
	}
	
	private static JsonElement getBodyAsJson(HttpResponse responseInfo) {
		return getBodyAsJson(responseContext(responseInfo));
	}

	private static JsonElement getBodyAsJson(ResponseExtractionContext responseContext) {
		try {
			JsonReader reader = new JsonReader(new StringReader(responseContext.bodyAsString()));
			reader.setLenient(true);
			JsonElement jsonElement = JsonParser.parseReader(reader);
			return jsonElement;
		} catch (Exception e) {
			MontoyaUtils.logError("Can not parse JSON Response. Error Message: " + e.getMessage());
		}
		return null;
	}
	
	public static ArrayList<Token> extractTokensFromMessages(HttpExchange[] messages) {
		HashMap<String, Token> tokenMap = new HashMap<String, Token>();
		String[] staticPatterns = Setting.getValueAsArray(Setting.Item.AUTOSET_PARAM_STATIC_PATTERNS);
		String[] dynamicPatterns = Setting.getValueAsArray(Setting.Item.AUTOSET_PARAM_DYNAMIC_PATTERNS);
		for(HttpExchange message : messages) {
			if(message.getRequest() != null) {
				HttpRequest requestInfo = message.getRequest();
				for(ParsedHttpParameter param : requestInfo.parameters()) {
					boolean process = false;
					boolean isDynamic = false;
					for(String pattern : staticPatterns) {
						if(param.name().toLowerCase().contains(pattern)) {
							process = true;
							break;
						}
					}
					for(String pattern : dynamicPatterns) {
						if(param.name().toLowerCase().contains(pattern)) {
							process = true;
							isDynamic = true;
							break;
						}
					}
					if(process) {
						boolean autoExtract = isDynamic;
						if(tokenMap.containsKey(param.name())) {
							autoExtract = tokenMap.get(param.name()).isAutoExtract();
						}
						Token token = null;
						String urlDecodedName;
						try {
							urlDecodedName = URLDecoder.decode(param.name(), StandardCharsets.UTF_8.toString());
						} catch (UnsupportedEncodingException e) {
							urlDecodedName = param.name();
						}
						String urlDecodedValue;
						try {
							urlDecodedValue = URLDecoder.decode(param.value(), StandardCharsets.UTF_8.toString());
						} catch (UnsupportedEncodingException e) {
							urlDecodedValue = param.value();
						}
						if(param.type() == HttpParameterType.COOKIE) {
							// Create Token with dynamic value
							token = new TokenBuilder()
									.setName(urlDecodedName)
									.setTokenLocationSet(EnumSet.of(TokenLocation.COOKIE))
									.setAutoExtractLocationSet(EnumSet.of(AutoExtractLocation.COOKIE))
									.setValue(param.value())
									.setExtractName(param.name())
									.setIsAutoExtract(true)
									.build();
						}
						if(param.type() == HttpParameterType.URL) {
							// Create Token with static value
							token = new TokenBuilder()
									.setName(urlDecodedName)
									.setTokenLocationSet(EnumSet.of(TokenLocation.URL))
									.setAutoExtractLocationSet(EnumSet.of(AutoExtractLocation.HTML))
									.setValue(urlDecodedValue)
									.setExtractName(urlDecodedName)
									.setIsAutoExtract(autoExtract)
									.setIsStaticValue(!autoExtract)
									.build();
						}
						if(param.type() == HttpParameterType.BODY) {
							// Create Token with static value
							token = new TokenBuilder()
									.setName(urlDecodedName)
									.setTokenLocationSet(EnumSet.of(TokenLocation.BODY))
									.setAutoExtractLocationSet(EnumSet.of(AutoExtractLocation.HTML))
									.setValue(urlDecodedValue)
									.setExtractName(urlDecodedName)
									.setIsAutoExtract(autoExtract)
									.setIsStaticValue(!autoExtract)
									.build();
						}
						if(param.type() == HttpParameterType.JSON) {
							token = new TokenBuilder()
									.setName(urlDecodedName)
									.setTokenLocationSet(EnumSet.of(TokenLocation.JSON))
									.setAutoExtractLocationSet(EnumSet.of(AutoExtractLocation.JSON))
									.setValue(urlDecodedValue)
									.setExtractName(urlDecodedName)
									.setIsAutoExtract(autoExtract)
									.setIsStaticValue(!autoExtract)
									.build();
						}
						if(token != null) {
							tokenMap.put(token.getName(), token);
						}
					}
				}
			}
			if(message.getResponse() != null) {
				HttpResponse responseInfo = message.getResponse();
				ResponseExtractionContext responseSnapshot = responseContext(responseInfo);
				for(Cookie cookie : responseInfo.cookies()) {
					Token token = new TokenBuilder()
							.setName(cookie.name())
							.setTokenLocationSet(EnumSet.of(TokenLocation.COOKIE))
							.setAutoExtractLocationSet(EnumSet.of(AutoExtractLocation.COOKIE))
							.setExtractName(cookie.name())
							.setIsAutoExtract(true)
							.build();
					tokenMap.put(token.getName(), token);
				}
				if(MontoyaUtils.mimeName(responseInfo.statedMimeType()).equals("JSON") || MontoyaUtils.mimeName(responseInfo.inferredMimeType()).equals("JSON")) {
					JsonElement jsonElement = getBodyAsJson(responseSnapshot);
					if(jsonElement != null) {
						createTokensFromJson(jsonElement, tokenMap);
					}
				}
			}
		}
		ArrayList<Token> tokenList = new ArrayList<Token>(tokenMap.values());
		tokenList.sort(Comparator.comparing(Token::sortString));
		return tokenList;
	}
	
	private static void createTokensFromJson(JsonElement jsonElement, HashMap<String, Token> tokenMap) {
		if (jsonElement.isJsonObject()) {
			JsonObject jsonObject = jsonElement.getAsJsonObject();
			for (Map.Entry<String, JsonElement> entry : jsonObject.entrySet()) {
				if (entry.getValue().isJsonArray() || entry.getValue().isJsonObject()) {
					createTokensFromJson(entry.getValue(), tokenMap);
				}
				if (entry.getValue().isJsonPrimitive()) {
					String[] staticPatterns = Setting.getValueAsArray(Setting.Item.AUTOSET_PARAM_STATIC_PATTERNS);
					for(String pattern : staticPatterns) {
						if(entry.getKey().toLowerCase().contains(pattern)) {
							Token token = new TokenBuilder()
									.setName(entry.getKey())
									.setTokenLocationSet(EnumSet.of(TokenLocation.JSON))
									.setAutoExtractLocationSet(EnumSet.of(AutoExtractLocation.JSON))
									.setExtractName(entry.getKey())
									.setIsAutoExtract(true)
									.build();
							tokenMap.put(token.getName(), token);
							break;
						}
					}
				}
			}
		}
		if (jsonElement.isJsonArray()) {
			for (JsonElement arrayJsonEl : jsonElement.getAsJsonArray()) {
				if (arrayJsonEl.isJsonArray() || arrayJsonEl.isJsonObject()) {
					createTokensFromJson(arrayJsonEl, tokenMap);
				}
			}
		}
	}
}
