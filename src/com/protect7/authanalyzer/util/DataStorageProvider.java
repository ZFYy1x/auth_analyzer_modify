package com.protect7.authanalyzer.util;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.filter.RequestFilter;

import burp.BurpExtender;

public class DataStorageProvider {

	private static final String STORAGE_KEY = "authAnalyzerSetupJson";
	
	public static String getSetupAsJsonString() {
		JsonArray sessionArray = new JsonArray();
		for (Session session : CurrentConfig.getCurrentConfig().getSessions()) {
			Gson gson = new GsonBuilder().setExclusionStrategies(session.getExclusionStrategy()).create();
			String sessionJsonAsString = gson.toJson(session);
			JsonObject sessionElement = JsonParser.parseString(sessionJsonAsString).getAsJsonObject();
			sessionElement.addProperty("name", session.getName());
			sessionArray.add(sessionElement);
		}

		JsonObject sessionsObject = new JsonObject();
		sessionsObject.add("sessions", sessionArray);

		JsonArray filterArray = new JsonArray();
		for (RequestFilter filter : CurrentConfig.getCurrentConfig().getRequestFilterList()) {
			JsonObject filterElement = JsonParser.parseString(filter.toJson()).getAsJsonObject();
			filterArray.add(filterElement);
		}
		sessionsObject.add("filters", filterArray);
		return sessionsObject.toString();
	}
	
	public static void saveSetup() {
		BurpExtender.api.persistence().extensionData().setString(STORAGE_KEY, getSetupAsJsonString());
	}
	
	public static String loadSetup() {
		return BurpExtender.api.persistence().extensionData().getString(STORAGE_KEY);
	}
}
