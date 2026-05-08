package com.protect7.authanalyzer.filter;

import java.awt.Color;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import com.protect7.authanalyzer.gui.util.HintCheckBox;
import com.protect7.authanalyzer.util.GenericHelper;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public abstract class RequestFilter {
	
	protected HintCheckBox onOffButton = null;
	protected final AtomicInteger amountOfFilteredRequests = new AtomicInteger(0);
	protected String[] stringLiterals = null;
	private final int filterIndex;
	private final String description;
	private final AtomicBoolean filteredUiUpdateQueued = new AtomicBoolean(false);
	private Timer filteredUiUpdateTimer;
	
	public RequestFilter(int filterIndex, String description) {
		this.filterIndex = filterIndex;
		this.description = description;
	}
	
	public void registerOnOffButton(HintCheckBox button) {
		onOffButton = button;
		onOffButton.putClientProperty("html.disable", null);
		onOffButton.setHint(getInfoText());
	}
	
	protected void incrementFiltered() {
		amountOfFilteredRequests.incrementAndGet();
		scheduleFilteredUiUpdate();
	}
	
	public void resetFilteredAmount() {
		amountOfFilteredRequests.set(0);
		filteredUiUpdateQueued.set(false);
		SwingUtilities.invokeLater(() -> {
			if (filteredUiUpdateTimer != null) {
				filteredUiUpdateTimer.stop();
			}
			updateFilteredUi();
		});
	}

	private void scheduleFilteredUiUpdate() {
		if(onOffButton == null) {
			return;
		}
		if (!filteredUiUpdateQueued.compareAndSet(false, true)) {
			return;
		}
		SwingUtilities.invokeLater(() -> {
			if (filteredUiUpdateTimer == null) {
				filteredUiUpdateTimer = new Timer(300, e -> {
					filteredUiUpdateQueued.set(false);
					updateFilteredUi();
				});
				filteredUiUpdateTimer.setRepeats(false);
			}
			if (!filteredUiUpdateTimer.isRunning()) {
				filteredUiUpdateTimer.start();
			} else {
				filteredUiUpdateQueued.set(false);
			}
		});
	}

	private void updateFilteredUi() {
		if(onOffButton == null) {
			return;
		}
		String textWihtoutFilterAmount = onOffButton.getText().split(" \\(")[0];
		int filtered = amountOfFilteredRequests.get();
		if (filtered > 0) {
			onOffButton.setText(textWihtoutFilterAmount + " (Filtered: " + filtered + ")");
			GenericHelper.uiUpdateAnimation(onOffButton, new Color(240, 110, 0));
		}
		else {
			onOffButton.setText(textWihtoutFilterAmount);
		}
	}
	
	public abstract boolean filterRequest(ToolType toolType, HttpRequest request, HttpResponse response);

	public abstract boolean hasStringLiterals();
	
	public String[] getFilterStringLiterals() {
		return stringLiterals;
	}
	
	public void setFilterStringLiterals(String[] stringLiterals) {
		this.stringLiterals = stringLiterals;
		onFilterStringLiteralsChanged();
		if(onOffButton != null) {
			onOffButton.setHint(getInfoText());
		}
	}

	protected void onFilterStringLiteralsChanged() {
	}
	
	public void setIsSelected(boolean selected) {
		onOffButton.setSelected(selected);
	}
	
	public String toJson() {
		String json = "{\"filterIndex\":"+filterIndex+",\"isSelected\":"+onOffButton.isSelected();
		if(!hasStringLiterals()) {
			json = json + "}";
		}
		else {
			json = json + ",\"stringLiterals\":[";
			for(int i=0; i<getFilterStringLiterals().length; i++) {
				if(i == getFilterStringLiterals().length-1) {
					json = json + "\""+getFilterStringLiterals()[i]+"\"";
				}
				else {
					json = json + "\""+getFilterStringLiterals()[i]+"\",";
				}
			}
			json = json + "]}";
		}
		return json;
	}
	
	public String getInfoText() {
		if (onOffButton != null) {
			if (hasStringLiterals()) {
				return "<html>" + getDescription() + "<br><strong><em>"
						+ GenericHelper.getArrayAsString(getFilterStringLiterals()) + "</em></strong></html>";
			} else {
				return getDescription();
			}
		}
		return "";
	}

	public int getFilterIndex() {
		return filterIndex;
	}

	public String getDescription() {
		return description;
	}
}
