package burp;

import java.util.ArrayList;
import java.util.List;

import com.protect7.authanalyzer.controller.HttpListener;
import com.protect7.authanalyzer.gui.main.MainPanel;
import com.protect7.authanalyzer.gui.util.AuthAnalyzerMenu;
import com.protect7.authanalyzer.util.DataStorageProvider;
import com.protect7.authanalyzer.util.Globals;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;

public class BurpExtender implements BurpExtension {

	public static MainPanel mainPanel;
	public static MontoyaApi api;
	private static final List<Registration> registrations = new ArrayList<Registration>();

	@Override
	public void initialize(MontoyaApi api) {
		BurpExtender.api = api;
		api.extension().setName(Globals.EXTENSION_NAME);
		mainPanel = new MainPanel();
		register(api.userInterface().registerSuiteTab(Globals.EXTENSION_NAME, mainPanel));
		register(api.userInterface().menuBar().registerMenu(new AuthAnalyzerMenu(Globals.EXTENSION_NAME)));
		HttpListener httpListener = new HttpListener();
		register(api.http().registerHttpHandler(httpListener));
		register(api.proxy().registerRequestHandler(httpListener));
		register(api.extension().registerUnloadingHandler(this::extensionUnloaded));
		api.logging().logToOutput(Globals.EXTENSION_NAME + " successfully started");
		api.logging().logToOutput("Version " + Globals.VERSION);
		api.logging().logToOutput("Created by " + Globals.AUTHOR);
	}

	public static void register(Registration registration) {
		if (registration != null) {
			registrations.add(registration);
		}
	}

	private void extensionUnloaded() {
		try {
			mainPanel.getConfigurationPanel().createSessionObjects(false);
			DataStorageProvider.saveSetup();
		}
		catch (Exception e) {
			api.logging().logToOutput("INFO: Session Setup not stored due to invalid data.");
		}
		for (Registration registration : new ArrayList<Registration>(registrations)) {
			if (registration != null && registration.isRegistered()) {
				registration.deregister();
			}
		}
		registrations.clear();
	}
}
