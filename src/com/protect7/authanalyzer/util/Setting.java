package com.protect7.authanalyzer.util;

import com.protect7.authanalyzer.entities.Range;

import burp.BurpExtender;

public class Setting {
	
	private final static String DELIMITER = ",";
	
	public static String[] getValueAsArray(Item settingItem) {
		String value = getPersistentSetting(settingItem.toString());
		if(value == null) {
			value = settingItem.defaultValue;
		}
		if(settingItem.getType() == Type.ARRAY) {
			String[] values = value.split(DELIMITER);
			for(int i=0; i<values.length; i++) {
				values[i] = values[i].trim();
			}
			return values;
		}
		return new String[] {};
	}
	
	public static boolean getValueAsBoolean(Item settingItem) {
		String value = getPersistentSetting(settingItem.toString());
		if(value == null) {
			value = settingItem.defaultValue;
		}
		if(settingItem.getType() == Type.BOOLEAN) {
			return Boolean.parseBoolean(value);
		}
		return false;
	}
	
	public static int getValueAsInteger(Item settingItem) {
		String value = getPersistentSetting(settingItem.toString());
		if(value == null) {
			value = settingItem.defaultValue;
		}
		if(settingItem.getType() == Type.INTEGER) {
			return Integer.parseInt(value);
		}
		return -1;
	}
	
	public static String getValueAsString(Item settingsItem) {
		String value = getPersistentSetting(settingsItem.toString());
		if(value == null) {
			value = settingsItem.getDefaultValue();
		}
		return value;
	}
	
	public static void setValue(Item settingItem, String value) {
		BurpExtender.callbacks.saveExtensionSetting(settingItem.toString(), value);
	}
	
	private static String getPersistentSetting(String name) {
		return BurpExtender.callbacks.loadExtensionSetting(name);
	}

	
	public enum Item {
		AUTOSET_PARAM_STATIC_PATTERNS("token,code,user,mail,pass,key,csrf,xsrf", 
				Type.ARRAY, "静态模式（用于自动设置参数）", null),
		AUTOSET_PARAM_DYNAMIC_PATTERNS("viewstate,eventvalidation,requestverificationtoken", Type.ARRAY,
				"动态模式（用于自动设置参数）", null),
		FORCE_HTTP_VERSION("AUTO", Type.STRING,
				"二次发送请求的 HTTP 协议版本（AUTO=不改动；可选 1.1/2/3）", null),
		NUMBER_OF_THREADS("5", Type.INTEGER, "线程数量（用于请求处理）", new Range(1,50)),
		DELAY_BETWEEN_REQUESTS("0", Type.INTEGER, "请求间延迟（毫秒）", new Range(0,60000)),
		ONLY_ONE_THREAD_IF_PROMT_FOR_INPUT("true", Type.BOOLEAN, 
				"如果存在提示输入参数则使用单线程", null),
		APPLY_FILTER_ON_MANUAL_REPEAT("false", Type.BOOLEAN, 
				"在手动请求重复时应用过滤器", null),
		STATUS_SAME_RESPONSE_CODE("true", Type.BOOLEAN, 
				"考虑响应代码以标记为状态相同", null),
		STATUS_SIMILAR_RESPONSE_CODE("true", Type.BOOLEAN, 
				"（条件1）考虑响应代码以标记为状态相似", null),
		STATUS_SIMILAR_RESPONSE_LENGTH("5", Type.INTEGER, 
				"（条件2）内容长度偏差百分比以标记为状态相似", new Range(1,100));
		
		private final String defaultValue;
		private final Type type;
		private final String description;
		private final Range range;
		
		private Item(String defaultValue, Type type, String description, Range range) {
			this.defaultValue = defaultValue;
			this.type = type;
			this.description = description;
			this.range = range;
		}
		
		public String getDefaultValue() {
			return defaultValue;
		}
		
		public Type getType() {
			return type;
		}

		public String getDescription() {
			return description;
		}
		
		public Range getRange() {
			return range;
		}
	}
	
	public enum Type {
		ARRAY(), STRING(), INTEGER(), BOOLEAN();
	}	
}