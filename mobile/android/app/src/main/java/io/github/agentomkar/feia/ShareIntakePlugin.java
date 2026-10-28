package io.github.agentomkar.feia;

import android.content.Intent;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

/**
 * Receives text shared into the app from the Android share sheet
 * (e.g. long-press an SMS or WhatsApp message -> Share -> FEIA Scam Check)
 * and hands it to the web layer.
 *
 * - getSharedText(): returns text that launched the app (cold start), once.
 * - "sharedText" event: fired when text is shared while the app is running.
 */
@CapacitorPlugin(name = "ShareIntake")
public class ShareIntakePlugin extends Plugin {

    private static final int MAX_CHARS = 20000;
    private String pending;

    @Override
    public void load() {
        pending = extract(getActivity().getIntent());
        // consume it so a configuration change doesn't re-trigger the scan
        getActivity().setIntent(new Intent(Intent.ACTION_MAIN));
    }

    @Override
    protected void handleOnNewIntent(Intent intent) {
        super.handleOnNewIntent(intent);
        String text = extract(intent);
        if (text != null) {
            JSObject data = new JSObject();
            data.put("text", text);
            notifyListeners("sharedText", data, true);
        }
    }

    @PluginMethod
    public void getSharedText(PluginCall call) {
        JSObject ret = new JSObject();
        ret.put("text", pending);
        pending = null;
        call.resolve(ret);
    }

    private static String extract(Intent intent) {
        if (intent == null || !Intent.ACTION_SEND.equals(intent.getAction())) return null;
        String type = intent.getType();
        if (type == null || !type.startsWith("text/")) return null;

        StringBuilder sb = new StringBuilder();
        CharSequence subject = intent.getCharSequenceExtra(Intent.EXTRA_SUBJECT);
        CharSequence text = intent.getCharSequenceExtra(Intent.EXTRA_TEXT);
        if (subject != null && subject.length() > 0 && (text == null || !text.toString().contains(subject))) {
            sb.append(subject).append('\n');
        }
        if (text != null) sb.append(text);

        String out = sb.toString().trim();
        if (out.isEmpty()) return null;
        return out.length() > MAX_CHARS ? out.substring(0, MAX_CHARS) : out;
    }
}
