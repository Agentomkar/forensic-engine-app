package io.github.agentomkar.feia;

import android.os.Bundle;

import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        // Local plugins must be registered before super.onCreate().
        registerPlugin(ShareIntakePlugin.class);
        super.onCreate(savedInstanceState);
    }
}
