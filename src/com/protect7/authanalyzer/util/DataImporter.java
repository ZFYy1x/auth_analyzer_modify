package com.protect7.authanalyzer.util;

import static burp.api.montoya.http.HttpService.httpService;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonToken;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.util.RequestTableModel;
import com.protect7.authanalyzer.montoya.HttpExchange;
import com.protect7.authanalyzer.montoya.MontoyaUtils;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

/**
 * 负责读取 DataExporter.createSnapshot 生成的"看板备份"JSON，
 * 并按当前配置的 Session（按名字匹配）把数据覆盖恢复到看板表格。
 *
 * 恢复语义：
 * <ul>
 *   <li>先完整解析并校验备份文件，任何解析错误都会中止（不清空现有数据）；</li>
 *   <li>解析通过后清空当前看板（Session 请求缓存 + 表格行），再按备份重建；</li>
 *   <li>ID 重新从当前计数器分配，避免与后续实时流量冲突；</li>
 *   <li>v2 备份含 sessionConfigs（会话完整配置），调用方可据此在当前配置中
 *       自动重建缺失的同名会话（含头替换/Token/匹配替换规则），避免会话数据被跳过；</li>
 *   <li>备份中会话名在当前配置中不存在时，该会话对应的数据被跳过并记录警告。</li>
 * </ul>
 *
 * 两阶段用法（v2 导入流程，见 CenterPanel.importBoardBackup）：
 * <ol>
 *   <li>{@link #prepare(File)}：解析并校验备份，得到行数据 + 备份会话名 + 会话配置；</li>
 *   <li>调用方在 EDT 上恢复缺失会话（SessionRestorer / ConfigurationPanel），并重建表格模型；</li>
 *   <li>{@link #restoreRows(ParsedSnapshot, CurrentConfig, RequestTableModel)}：清空看板并灌入数据。</li>
 * </ol>
 */
public class DataImporter {

	/** 兼容的备份版本：v1（仅数据）、v2（数据 + 会话配置） */
	private static final int SUPPORTED_VERSION_MIN = 1;

	private DataImporter() {
	}

	/** 恢复结果统计。error 为 null 表示成功。 */
	public static class ImportResult {
		public int totalRows = 0;
		public int restoredRows = 0;
		public int skippedInvalidRows = 0;
		public int matchedSessionEntries = 0;
		public int skippedSessionEntries = 0;
		public List<String> unknownSessions = new ArrayList<String>();
		public String error = null;
	}

	/** 解析后的备份快照（prepare 产出，restoreRows 消费） */
	public static class ParsedSnapshot {
		public final List<ParsedRow> rows = new ArrayList<ParsedRow>();
		/** 备份中出现过的会话名（有数据条目的），按出现顺序 */
		public final LinkedHashSet<String> backupSessionNames = new LinkedHashSet<String>();
		/** v2 备份的会话完整配置（与 DataStorageProvider setup JSON 的 sessions 数组同构）；v1 为 null */
		public JsonArray sessionConfigs;
		public int version;
	}

	/** 备份中单条 Session 结果 */
	private static class ParsedSessionData {
		String sessionName;
		String statusName;
		String infoText;
		int statusCode;
		int responseContentLength;
		byte[] requestBytes;
		byte[] responseBytes;
	}

	/** 备份中一行看板数据 */
	private static class ParsedRow {
		int id;
		String comment;
		boolean marked;
		String infoText;
		String method;
		String url;
		int statusCode;
		int responseContentLength;
		String host;
		int port;
		boolean secure;
		byte[] requestBytes;
		byte[] responseBytes;
		List<ParsedSessionData> sessionData = new ArrayList<ParsedSessionData>();
	}

	/**
	 * 阶段一：解析并校验备份文件。失败抛 IOException，调用方直接提示。
	 * 不触碰当前看板数据。
	 */
	public static ParsedSnapshot prepare(File file) throws IOException {
		ParsedSnapshot snapshot = new ParsedSnapshot();
		parse(file, snapshot);
		Collections.sort(snapshot.rows, new Comparator<ParsedRow>() {
			@Override
			public int compare(ParsedRow left, ParsedRow right) {
				return Integer.compare(left.id, right.id);
			}
		});
		for (ParsedRow row : snapshot.rows) {
			for (ParsedSessionData sessionData : row.sessionData) {
				if (sessionData.sessionName != null) {
					snapshot.backupSessionNames.add(sessionData.sessionName);
				}
			}
		}
		return snapshot;
	}

	/**
	 * 阶段二：清空当前看板并把备份行数据恢复到指定表格模型。
	 * 调用方需保证：备份中期望恢复的会话在 config 中已存在（必要时先经会话恢复），
	 * 且传入的 tableModel 即为最终展示的模型（其列结构含全部会话列）。
	 */
	public static ImportResult restoreRows(ParsedSnapshot snapshot, CurrentConfig config,
			RequestTableModel tableModel) {
		ImportResult result = new ImportResult();
		try {
			result.totalRows = snapshot.rows.size();

			// 按名字建立当前 Session 索引，并收集缺失会话
			Map<String, Session> sessionsByName = new LinkedHashMap<String, Session>();
			for (Session session : config.getSessions()) {
				sessionsByName.put(session.getName(), session);
			}
			LinkedHashSet<String> unknownSet = new LinkedHashSet<String>();
			for (ParsedRow row : snapshot.rows) {
				for (ParsedSessionData sessionData : row.sessionData) {
					if (sessionData.sessionName == null
							|| sessionsByName.get(sessionData.sessionName) == null) {
						unknownSet.add(sessionData.sessionName);
					}
				}
			}
			result.unknownSessions.addAll(unknownSet);

			// 解析通过：清空当前看板后重建
			config.clearSessionRequestMaps();
			tableModel.clearRequestMap();

			// 批量重建：先构造全部 OriginalRequestResponse(并为每行写入各 Session 结果)，
			// 再一次交给表格批量建立索引并触发一次刷新，避免逐行走实时去重/EDT 事件管线。
			ArrayList<OriginalRequestResponse> rebuiltRows = new ArrayList<OriginalRequestResponse>(snapshot.rows.size());
			for (ParsedRow row : snapshot.rows) {
				try {
					OriginalRequestResponse originalRequestResponse = buildRow(row, sessionsByName, config, result);
					if (originalRequestResponse != null) {
						rebuiltRows.add(originalRequestResponse);
					}
				} catch (Exception rowException) {
					result.skippedInvalidRows++;
					MontoyaUtils.logError("Skipped row (id " + row.id + ") during snapshot restore. "
							+ rowException.getMessage());
				}
			}
			if (!rebuiltRows.isEmpty()) {
				tableModel.bulkRebuildForRestore(rebuiltRows);
			}
		} catch (Exception e) {
			result.error = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
			MontoyaUtils.logError("Board snapshot restore failed. " + result.error);
		}
		return result;
	}

	/**
	 * 一步式恢复（不自动重建缺失会话）。保留给简单场景使用；
	 * CenterPanel 的导入流程走 prepare/restoreRows 两阶段以支持会话自动恢复。
	 */
	public static ImportResult restore(File file, CurrentConfig config, RequestTableModel tableModel) {
		try {
			return restoreRows(prepare(file), config, tableModel);
		} catch (IOException e) {
			ImportResult result = new ImportResult();
			result.error = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
			MontoyaUtils.logError("Board snapshot restore failed. " + result.error);
			return result;
		}
	}

	/**
	 * 由备份中的一行构造看板行，并把该行的各 Session 结果写入对应 Session。
	 *
	 * @return 构造成功的 OriginalRequestResponse；该行无效(缺报文/无法重建)时返回 null。
	 */
	private static OriginalRequestResponse buildRow(ParsedRow row, Map<String, Session> sessionsByName,
			CurrentConfig config, ImportResult result) {
		if (row.requestBytes == null || row.requestBytes.length == 0 || row.host == null || row.host.isEmpty()) {
			result.skippedInvalidRows++;
			return null;
		}
		int effectivePort = row.port;
		if (effectivePort <= 0) {
			effectivePort = row.secure ? 443 : 80;
		}
		HttpService service = httpService(row.host, effectivePort, row.secure);
		HttpRequest request = MontoyaUtils.requestFromBytes(service, row.requestBytes);
		if (request == null) {
			result.skippedInvalidRows++;
			return null;
		}
		HttpResponse response = MontoyaUtils.responseFromBytes(row.responseBytes);
		HttpExchange exchange = new HttpExchange(request, response);
		int newId = config.getNextMapId();
		OriginalRequestResponse originalRequestResponse = new OriginalRequestResponse(newId, exchange,
				row.method == null ? request.method() : row.method,
				row.url == null ? MontoyaUtils.pathAndQuery(request) : row.url, row.infoText, row.statusCode,
				row.responseContentLength);
		if (row.comment != null) {
			originalRequestResponse.setComment(row.comment);
		}
		originalRequestResponse.setMarked(row.marked);
		result.restoredRows++;

		for (ParsedSessionData sessionData : row.sessionData) {
			Session session = sessionData.sessionName == null ? null : sessionsByName.get(sessionData.sessionName);
			if (session == null) {
				result.skippedSessionEntries++;
				continue;
			}
			HttpExchange sessionExchange = null;
			if (sessionData.requestBytes != null && sessionData.requestBytes.length > 0) {
				HttpRequest sessionRequest = MontoyaUtils.requestFromBytes(service, sessionData.requestBytes);
				if (sessionRequest != null) {
					sessionExchange = new HttpExchange(sessionRequest,
							MontoyaUtils.responseFromBytes(sessionData.responseBytes));
				}
			}
			BypassConstants status = null;
			if (sessionData.statusName != null) {
				try {
					status = BypassConstants.valueOf(sessionData.statusName);
				} catch (Exception ignore) {
					status = BypassConstants.NA;
				}
			}
			AnalyzerRequestResponse analyzerRequestResponse = new AnalyzerRequestResponse(sessionExchange, status,
					sessionData.infoText, sessionData.statusCode, sessionData.responseContentLength);
			session.putRequestResponse(newId, analyzerRequestResponse);
			result.matchedSessionEntries++;
		}
		return originalRequestResponse;
	}

	private static void parse(File file, ParsedSnapshot snapshot) throws IOException {
		JsonReader reader = new JsonReader(
				new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8));
		try {
			String format = null;
			int version = -1;
			reader.beginObject();
			while (reader.hasNext()) {
				String name = reader.nextName();
				if ("format".equals(name)) {
					format = reader.nextString();
				} else if ("version".equals(name)) {
					version = reader.nextInt();
				} else if ("exportedAt".equals(name)) {
					reader.skipValue();
				} else if ("sessionNames".equals(name)) {
					reader.skipValue();
				} else if ("sessionConfigs".equals(name)) {
					snapshot.sessionConfigs = parseSessionConfigs(reader);
				} else if ("rows".equals(name)) {
					reader.beginArray();
					while (reader.hasNext()) {
						snapshot.rows.add(parseRow(reader));
					}
					reader.endArray();
				} else {
					reader.skipValue();
				}
			}
			reader.endObject();
			if (!DataExporter.SNAPSHOT_FORMAT.equals(format)) {
				throw new IOException("文件不是有效的看板备份（format 不匹配）");
			}
			if (version < SUPPORTED_VERSION_MIN || version > DataExporter.SNAPSHOT_VERSION) {
				throw new IOException("不支持的备份版本: " + version + "（当前支持 "
						+ SUPPORTED_VERSION_MIN + "~" + DataExporter.SNAPSHOT_VERSION + "）");
			}
			snapshot.version = version;
		} finally {
			reader.close();
		}
	}

	/** 读取顶层 sessionConfigs 数组为原始 JsonArray（供会话恢复按名取配置） */
	private static JsonArray parseSessionConfigs(JsonReader reader) throws IOException {
		// JsonReader 与 JsonParser 混用需整体读取：先以 JsonParser 从 reader 解流
		return JsonParser.parseReader(reader).getAsJsonArray();
	}

	private static ParsedRow parseRow(JsonReader reader) throws IOException {
		ParsedRow row = new ParsedRow();
		reader.beginObject();
		while (reader.hasNext()) {
			String name = reader.nextName();
			if ("id".equals(name)) {
				row.id = reader.nextInt();
			} else if ("comment".equals(name)) {
				row.comment = nextNullableString(reader);
			} else if ("marked".equals(name)) {
				row.marked = reader.nextBoolean();
			} else if ("infoText".equals(name)) {
				row.infoText = nextNullableString(reader);
			} else if ("method".equals(name)) {
				row.method = nextNullableString(reader);
			} else if ("url".equals(name)) {
				row.url = nextNullableString(reader);
			} else if ("statusCode".equals(name)) {
				row.statusCode = reader.nextInt();
			} else if ("responseContentLength".equals(name)) {
				row.responseContentLength = reader.nextInt();
			} else if ("host".equals(name)) {
				row.host = nextNullableString(reader);
			} else if ("port".equals(name)) {
				row.port = reader.nextInt();
			} else if ("secure".equals(name)) {
				row.secure = reader.nextBoolean();
			} else if ("requestB64".equals(name)) {
				row.requestBytes = decodeBase64(nextNullableString(reader), row.id);
			} else if ("responseB64".equals(name)) {
				row.responseBytes = decodeBase64(nextNullableString(reader), row.id);
			} else if ("sessionData".equals(name)) {
				row.sessionData = parseSessionData(reader, row.id);
			} else {
				reader.skipValue();
			}
		}
		reader.endObject();
		return row;
	}

	private static List<ParsedSessionData> parseSessionData(JsonReader reader, int rowId) throws IOException {
		List<ParsedSessionData> sessionDataList = new ArrayList<ParsedSessionData>();
		reader.beginArray();
		while (reader.hasNext()) {
			ParsedSessionData sessionData = new ParsedSessionData();
			reader.beginObject();
			while (reader.hasNext()) {
				String name = reader.nextName();
				if ("sessionName".equals(name)) {
					sessionData.sessionName = nextNullableString(reader);
				} else if ("statusName".equals(name)) {
					sessionData.statusName = nextNullableString(reader);
				} else if ("infoText".equals(name)) {
					sessionData.infoText = nextNullableString(reader);
				} else if ("statusCode".equals(name)) {
					sessionData.statusCode = reader.nextInt();
				} else if ("responseContentLength".equals(name)) {
					sessionData.responseContentLength = reader.nextInt();
				} else if ("requestB64".equals(name)) {
					sessionData.requestBytes = decodeBase64(nextNullableString(reader), rowId);
				} else if ("responseB64".equals(name)) {
					sessionData.responseBytes = decodeBase64(nextNullableString(reader), rowId);
				} else {
					reader.skipValue();
				}
			}
			reader.endObject();
			sessionDataList.add(sessionData);
		}
		reader.endArray();
		return sessionDataList;
	}

	private static String nextNullableString(JsonReader reader) throws IOException {
		if (reader.peek() == JsonToken.NULL) {
			reader.nextNull();
			return null;
		}
		return reader.nextString();
	}

	private static byte[] decodeBase64(String value, int rowId) {
		if (value == null) {
			return null;
		}
		try {
			return Base64.getDecoder().decode(value);
		} catch (IllegalArgumentException e) {
			throw new IllegalStateException("行 " + rowId + " 的 Base64 数据损坏: " + e.getMessage());
		}
	}
}
