// Tessera Face Unlock Status — GNOME Shell 48 (ESM) lock-screen status glyph.
//
// PROTOTYPE / DESIGN REFERENCE — not wired into the tessera .deb yet.
// See docs/research/gui-login-design.md and docs/adr/0022-*.
//
// This extension is a PURE VIEW. It subscribes to the root-owned system-bus
// signal org.tessera.ScanState1.StateChanged(s) and draws an abstract glyph on
// the lock screen. It makes NO authentication decision, calls NO auth method,
// and treats the signal as advisory only (PAM + the TPM-sealed key are the sole
// authority). A forged signal is therefore cosmetic, never a bypass.

import GObject from 'gi://GObject';
import Gio from 'gi://Gio';
import Clutter from 'gi://Clutter';
import St from 'gi://St';

import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';

const FACE_STATUS_IFACE = `
<node>
  <interface name="org.tessera.ScanState1">
    <signal name="StateChanged">
      <arg type="s" name="state"/>
    </signal>
    <property name="State" type="s" access="read"/>
  </interface>
</node>`;

// Known states only; anything else is clamped to 'idle' (defensive — a garbage
// or forged payload must never throw on the lock screen).
const STATE_UI = {
    'idle':       {icon: 'face-smile-symbolic',        label: '',                       css: 'tessera-idle'},
    'scanning':   {icon: 'view-reveal-symbolic',       label: 'Looking for you…',       css: 'tessera-scanning'},
    'need-light': {icon: 'display-brightness-symbolic', label: 'Need more light…',      css: 'tessera-scanning'},
    'no-face':    {icon: 'view-reveal-symbolic',       label: 'Look at the camera…',    css: 'tessera-scanning'},
    'matched':    {icon: 'emblem-ok-symbolic',         label: 'Got it',                 css: 'tessera-matched'},
    'no-match':   {icon: 'action-unavailable-symbolic', label: 'Couldn’t recognize you', css: 'tessera-failed'},
};

const FaceGlyph = GObject.registerClass(
class FaceGlyph extends St.BoxLayout {
    _init() {
        super._init({
            orientation: Clutter.Orientation.HORIZONTAL, // GNOME 48: not `vertical: true`
            style_class: 'tessera-face-glyph',
            x_align: Clutter.ActorAlign.CENTER,
            y_align: Clutter.ActorAlign.CENTER,
            reactive: false, // never grab input on the lock screen
        });
        this._icon = new St.Icon({
            icon_name: STATE_UI.idle.icon,
            style_class: 'tessera-face-icon',
            icon_size: 48,
        });
        this._label = new St.Label({text: '', style_class: 'tessera-face-label',
            y_align: Clutter.ActorAlign.CENTER});
        this.add_child(this._icon);
        this.add_child(this._label);
    }

    setState(state) {
        const ui = STATE_UI[state] ?? STATE_UI.idle;
        for (const s of Object.values(STATE_UI))
            this.remove_style_class_name(s.css);
        this.add_style_class_name(ui.css);
        this._icon.icon_name = ui.icon;
        this._label.text = ui.label;
        this.visible = state !== 'idle';
    }
});

export default class TesseraFaceStatusExtension extends Extension {
    constructor(metadata) {
        super(metadata);
        this._proxy = null;
        this._signalId = 0;
        this._glyph = null;
        this._sessionId = 0;
        this._lockedChangedId = 0;
        this._cancellable = null;
    }

    enable() {
        this._cancellable = new Gio.Cancellable();

        // Root daemon → system bus. Sender-filtered by the well-known name:
        // a Gio.DBusProxy resolves 'org.tessera.ScanState1' to its current
        // owner's unique name, so signals from any other connection are dropped.
        const FaceStatusProxy = Gio.DBusProxy.makeProxyWrapper(FACE_STATUS_IFACE);
        this._proxy = FaceStatusProxy(
            Gio.DBus.system,
            'org.tessera.ScanState1',
            '/org/tessera/ScanState1',
            (proxy, error) => {
                if (error) {
                    console.error(`Tessera: FaceStatus proxy failed: ${error}`);
                    return;
                }
                this._signalId = proxy.connectSignal('StateChanged',
                    (_p, _sender, [state]) => this._onStateChanged(state));
                if (proxy.State)
                    this._onStateChanged(proxy.State);
            },
            this._cancellable);

        // Documented, stable lock/unlock trigger.
        this._sessionId = Main.sessionMode.connect('updated', () => this._sync());
        if (Main.screenShield) {
            this._lockedChangedId =
                Main.screenShield.connect('locked-changed', () => this._sync());
        }
        this._sync();
    }

    _onStateChanged(state) {
        if (this._glyph)
            this._glyph.setState(state);
    }

    _sync() {
        if (Main.sessionMode.currentMode === 'unlock-dialog')
            this._mount();
        else
            this._unmount();
    }

    // ── UNSTABLE PRIVATE INTERNALS — verify on every GNOME bump ──────────────
    // Main.screenShield._dialog is the UnlockDialog; it is created lazily and
    // destroyed on unlock, so we (re)mount on each lock. We only ADD a child
    // (additive monkeypatch = lowest breakage risk); we never replace actors,
    // and never anchor to _authPrompt (it blinks in/out). Any missing field
    // degrades to "no glyph" rather than crashing the Shell.
    _mount() {
        if (this._glyph)
            return;
        const dialog = Main.screenShield?._dialog;
        if (!dialog)
            return; // not ready; retry on the next 'updated'
        this._glyph = new FaceGlyph();
        dialog.add_child(this._glyph);
        this._glyph.set({x_align: Clutter.ActorAlign.CENTER, y_align: Clutter.ActorAlign.START});
        this._glyph.setState(this._proxy?.State ?? 'idle');
    }

    _unmount() {
        if (this._glyph) {
            this._glyph.destroy();
            this._glyph = null;
        }
    }

    disable() {
        this._cancellable?.cancel();
        this._cancellable = null;
        if (this._proxy && this._signalId) {
            this._proxy.disconnectSignal(this._signalId);
            this._signalId = 0;
        }
        this._proxy = null;
        if (this._sessionId) {
            Main.sessionMode.disconnect(this._sessionId);
            this._sessionId = 0;
        }
        if (this._lockedChangedId && Main.screenShield) {
            Main.screenShield.disconnect(this._lockedChangedId);
            this._lockedChangedId = 0;
        }
        this._unmount();
    }
}
