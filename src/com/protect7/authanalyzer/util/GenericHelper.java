package com.protect7.authanalyzer.util;

import java.awt.Color;
import java.awt.Component;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JFrame;
import javax.swing.Timer;
import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.gui.main.ConfigurationPanel;
import com.protect7.authanalyzer.montoya.HttpExchange;
import com.protect7.authanalyzer.util.Setting.Item;
import burp.api.montoya.core.ToolType;

public class GenericHelper {
	
	public static void repeatRequests(HttpExchange[] messages, ConfigurationPanel configurationPanel) {
		if(configurationPanel.isPaused()) {
			configurationPanel.pauseButtonPressed();
		}
		if(!CurrentConfig.getCurrentConfig().isRunning()) {
			configurationPanel.startStopButtonPressed();
		}
		if(CurrentConfig.getCurrentConfig().isRunning()) {
			boolean applyFilters = Setting.getValueAsBoolean(Item.APPLY_FILTER_ON_MANUAL_REPEAT);
			for(HttpExchange message : messages) {
				boolean isFiltered = false;
				if(applyFilters) {
					for(int i=0; i<CurrentConfig.getCurrentConfig().getRequestFilterList().size(); i++) {
						RequestFilter filter = CurrentConfig.getCurrentConfig().getRequestFilterAt(i);
						if(filter.filterRequest(ToolType.PROXY, message.getRequest(), message.getResponse())) {
							isFiltered = true;
							break;
						}
					}
				}
				if(!isFiltered) {
					CurrentConfig.getCurrentConfig().performAuthAnalyzerRequest(message);
				}
			}
		}
	}
	
	public static void uiUpdateAnimation(Component component, Color animationColor) {
		Color foregroundColor = component.getForeground();
		if(component != null && foregroundColor != null && foregroundColor.getRGB() != animationColor.getRGB()) {
			component.setForeground(animationColor);
			Timer timer = new Timer(5000, new ActionListener() {
				
				@Override
				public void actionPerformed(ActionEvent e) {
					component.setForeground(foregroundColor);
				}
			});
			timer.setRepeats(false);
			timer.start();
		}
	}
	
	public static void animateBurpExtensionTab() {
		// Disabled: avoid highlighting/flashing the Burp extension tab when new traffic arrives.
		// Users requested removing the tab highlight reminder.
		return;
	}
	
	public static Color getErrorBgColor() {
		return new Color(255, 102, 102);
	}
	
	public static String getArrayAsString(String[] array) {
		String arrayAsString = "";
		if (array != null) {
			for (String arrayPart : array) {
				if (arrayAsString.equals("")) {
					arrayAsString = arrayPart;
				} else {
					arrayAsString += ", " + arrayPart;
				}
			}
		}
		return arrayAsString;
	}
	
	public static JFrame getBurpFrame() {
        for (Frame f : Frame.getFrames()) {
            if (f.isVisible() && f.getTitle().startsWith(("Burp Suite"))) {
                return (JFrame) f;
            }
        }
        return null;
    }
}
