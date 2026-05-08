package com.protect7.authanalyzer.gui.util;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
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
						boolean contained = entry.getStringValue(3).toString().contains(searchText);
						if((contained && !negativeSearch.isSelected()) || (!contained && negativeSearch.isSelected())) {
							doShow = true;
						}
					}
					if(searchInRequest.isSelected() && !doShow) {	
						try {
							int id = Integer.parseInt(entry.getStringValue(0));
							String requestContent = getRequestContent(id);
							if (requestContent != null) {
								boolean contained = requestContent.contains(searchText);
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
								boolean contained = responseContent.contains(searchText);
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
