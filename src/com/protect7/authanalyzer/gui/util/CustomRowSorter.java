package com.protect7.authanalyzer.gui.util;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import javax.swing.JCheckBox;
import javax.swing.RowFilter;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.table.TableRowSorter;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.main.CenterPanel;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;

public class CustomRowSorter extends TableRowSorter<RequestTableModel> {
	
	// 搜索索引缓存
	private static final int SEARCH_CONTENT_CACHE_SIZE = 100;
	private final Map<Integer, String> requestContentCache = createSearchContentCache();
	private final Map<Integer, String> responseContentCache = createSearchContentCache();
	// 通配符搜索模式缓存（{%} 表示任意字符）
	private static final String WILDCARD_TOKEN = "{%}";
	private static String cachedPatternKey = null;
	private static Pattern cachedPattern = null;
	
	public CustomRowSorter(CenterPanel centerPanel, RequestTableModel tableModel, JCheckBox showOnlyMarked, JCheckBox showDuplicates, JCheckBox showBypassed, 
			JCheckBox showPotentialBypassed, JCheckBox showNotBypassed, JCheckBox showNA, PlaceholderTextField filterText,
			JCheckBox searchInPath, JCheckBox searchInRequest, JCheckBox searchInResponse, JCheckBox negativeSearch) {
		super(tableModel);
		showOnlyMarked.addActionListener(e -> tableModel.fireTableDataChanged());
		showDuplicates.addActionListener(e -> tableModel.fireTableDataChanged());
		showBypassed.addActionListener(e -> tableModel.fireTableDataChanged());
		showPotentialBypassed.addActionListener(e -> tableModel.fireTableDataChanged());
		showNotBypassed.addActionListener(e -> tableModel.fireTableDataChanged());
		showNA.addActionListener(e -> tableModel.fireTableDataChanged());
		filterText.addActionListener(e -> tableModel.fireTableDataChanged());
		setMaxSortKeys(1);
        setSortKeys(Collections.singletonList(new RowSorter.SortKey(0, SortOrder.DESCENDING)));
		// 避免每次数据更新都自动重新排序，降低大数据量时的卡顿
		setSortsOnUpdates(false);
		
		RowFilter<Object, Object> filter = new RowFilter<Object, Object>() {
			
			public boolean include(Entry<?, ?> entry) {
				String searchText = filterText.getText();
				if(searchText != null && !searchText.equals("")) {
					boolean doShow = false;
				if(searchInPath.isSelected()) {
					boolean contained = matchesSearch(entry.getStringValue(3).toString(), searchText);
						if((contained && !negativeSearch.isSelected()) || (!contained && negativeSearch.isSelected())) {
							doShow = true;
						}
					}
					if(searchInRequest.isSelected() && !doShow) {	
						try {
							int id = Integer.parseInt(entry.getStringValue(0));
							String requestContent = getRequestContent(id);
							if (requestContent != null) {
								boolean contained = matchesSearch(requestContent, searchText);
								if((contained && !negativeSearch.isSelected()) || (!contained && negativeSearch.isSelected())) {
									doShow = true;
								}
							}
						}
						catch (Exception e) {
							e.printStackTrace();
						}
					}
					if(searchInResponse.isSelected() && !doShow) {	
						try {
							int id = Integer.parseInt(entry.getStringValue(0));
							String responseContent = getResponseContent(id);
							if (responseContent != null) {
								boolean contained = matchesSearch(responseContent, searchText);
								if((contained && !negativeSearch.isSelected()) || (!contained && negativeSearch.isSelected())) {
									doShow = true;
								}
							}
						}
						catch (Exception e) {
							e.printStackTrace();
						}
					}
					if(!doShow && (searchInPath.isSelected() || searchInResponse.isSelected() || searchInRequest.isSelected())) {
						return false;
					}
				}
				if(showOnlyMarked.isSelected()) {
					OriginalRequestResponse requestResponse = tableModel.getOriginalRequestResponseById(Integer.parseInt(entry.getStringValue(0)));
					if(requestResponse != null && !requestResponse.isMarked()) {
						return false;
					}
				}
				// 勾选时启用去重过滤；未勾选时不过滤重复项
				if(showDuplicates.isSelected()) {
					int id = Integer.parseInt(entry.getStringValue(0));
					// 折叠相同请求；非GET包含请求体签名
					if(tableModel.isDuplicateByRequestSignature(id)) {
						return false;
					}
				}
				if(showBypassed.isSelected()) {
					for(int i = entry.getValueCount()-1; i>4; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.SAME.toString())) {
							return true;
						}
					}
				}
				if(showPotentialBypassed.isSelected()) {
					for(int i = entry.getValueCount()-1; i>4; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.SIMILAR.toString())) {
							return true;
						}
					}
				}
				if(showNotBypassed.isSelected()) {
					for(int i = entry.getValueCount()-1; i>4; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.DIFFERENT.toString())) {
							return true;
						}
					}
				}
				if(showNA.isSelected()) {
					for(int i = entry.getValueCount()-1; i>4; i--) {
						if(entry.getStringValue(i).equals(BypassConstants.NA.toString())) {
							return true;
						}
					}
				}
				// 兜底 1: 状态白名单一个都未勾选 = 不做状态过滤(放行全部), 避免"全不勾反而全滤"死锁
				if(!showBypassed.isSelected() && !showPotentialBypassed.isSelected()
						&& !showNotBypassed.isSelected() && !showNA.isSelected()) {
					return true;
				}
				// 兜底 2: 行内无任何 session 状态判定(如导入的备份中会话名未匹配当前配置)
				//         视为"无数据"状态, 跟随 NA 白名单显示, 避免恢复的数据被过滤成不可见
				if(showNA.isSelected()) {
					boolean hasStatusValue = false;
					for(int i = entry.getValueCount()-1; i>4 && !hasStatusValue; i--) {
						if(entry.getValue(i) instanceof BypassConstants) {
							hasStatusValue = true;
						}
					}
					if(!hasStatusValue) {
						return true;
					}
				}
				return false;
			}
		};
		
		setRowFilter(filter);
	}

	private Map<Integer, String> createSearchContentCache() {
		return new LinkedHashMap<Integer, String>(SEARCH_CONTENT_CACHE_SIZE, 0.75f, true) {
			private static final long serialVersionUID = 1L;

			@Override
			protected boolean removeEldestEntry(Map.Entry<Integer, String> eldest) {
				return size() > SEARCH_CONTENT_CACHE_SIZE;
			}
		};
	}

	/**
	 * 判断内容是否命中搜索词。
	 * 普通搜索词：等价于 contains 子串匹配。
	 * 含 {%} 通配符：将 {%} 视为"匹配任意字符"，其余部分按字面量处理，
	 * 例如 /api/reports/authorized/{%}/html 可命中 /api/reports/authorized/123/html。
	 */
	private static boolean matchesSearch(String content, String searchText) {
		if (content == null || searchText == null) {
			return false;
		}
		if (!searchText.contains(WILDCARD_TOKEN)) {
			return content.contains(searchText);
		}
		return getWildcardPattern(searchText).matcher(content).find();
	}

	/**
	 * 将含 {%} 的搜索词编译为正则（带缓存），字面量部分自动转义，
	 * 仅 {%} 被解释为 .*，避免用户输入的正则元字符产生歧义。
	 */
	private static Pattern getWildcardPattern(String searchText) {
		if (!searchText.equals(cachedPatternKey) || cachedPattern == null) {
			StringBuilder regex = new StringBuilder();
			int from = 0;
			int idx;
			while ((idx = searchText.indexOf(WILDCARD_TOKEN, from)) >= 0) {
				regex.append(Pattern.quote(searchText.substring(from, idx)));
				regex.append(".*");
				from = idx + WILDCARD_TOKEN.length();
			}
			regex.append(Pattern.quote(searchText.substring(from)));
			cachedPattern = Pattern.compile(regex.toString());
			cachedPatternKey = searchText;
		}
		return cachedPattern;
	}
	
	private String getRequestContent(int id) {
		if (requestContentCache.containsKey(id)) {
			return requestContentCache.get(id);
		}
		String requestContent = null;
		try {
			for (Session session : CurrentConfig.getCurrentConfig().getSessions()) {
				AnalyzerRequestResponse arr = session.getRequestResponseMap().get(id);
				if (arr != null && arr.getRequestResponse() != null) {
					byte[] requestBytes = arr.getRequestResponse().getRequestBytes();
					if (requestBytes != null) {
						requestContent = new String(requestBytes);
						break;
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		requestContentCache.put(id, requestContent);
		return requestContent;
	}

	private String getResponseContent(int id) {
		if (responseContentCache.containsKey(id)) {
			return responseContentCache.get(id);
		}
		String responseContent = null;
		try {
			for (Session session : CurrentConfig.getCurrentConfig().getSessions()) {
				AnalyzerRequestResponse arr = session.getRequestResponseMap().get(id);
				if (arr != null && arr.getRequestResponse() != null) {
					byte[] responseBytes = arr.getRequestResponse().getResponseBytes();
					if (responseBytes != null) {
						responseContent = new String(responseBytes);
						break;
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		responseContentCache.put(id, responseContent);
		return responseContent;
	}

	/**
	 * 清理索引缓存
	 */
	public void clearIndex() {
		requestContentCache.clear();
		responseContentCache.clear();
	}
	
	/**
	 * 重建索引
	 */
	public void rebuildIndex() {
		clearIndex();
	}
}
