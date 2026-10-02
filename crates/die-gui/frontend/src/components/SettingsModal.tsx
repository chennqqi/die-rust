import { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { X } from 'lucide-react';

// --- Settings types (mirror Rust AppSettings) ---

interface ViewSettings {
  theme: string;
  language: string;
  stay_on_top: boolean;
  advanced: boolean;
}

interface FileSettings {
  last_directory: string;
  recent_files: string[];
  save_backup: boolean;
}

interface ScanFlagDefaults {
  recursive: boolean;
  deep: boolean;
  heuristic: boolean;
  verbose: boolean;
  aggressive: boolean;
  alltypes: boolean;
  overlay: boolean;
  resources: boolean;
  archives: boolean;
  first_wrapper_only: boolean;
  hide_unknown: boolean;
  no_dedup: boolean;
}

interface ScanSettings {
  scan_after_open: boolean;
  hide_unknown: boolean;
  sort: boolean;
  log_profiling: boolean;
  flags: ScanFlagDefaults;
}

interface DatabaseSettings {
  main_path: string;
  extra_path: string;
  custom_path: string;
  extra_enabled: boolean;
  custom_enabled: boolean;
}

interface EngineSettings {
  die_enabled: boolean;
  nfd_enabled: boolean;
  peid_enabled: boolean;
  yara_enabled: boolean;
}

interface OnlineToolsSettings {
  virustotal_apikey: string;
}

interface ShortcutSettings {
  open_file: string;
  save_results: string;
  scan: string;
  stop_scan: string;
  toggle_hex: string;
  toggle_strings: string;
  open_settings: string;
  quit: string;
}

interface AppSettings {
  view: ViewSettings;
  file: FileSettings;
  scan: ScanSettings;
  database: DatabaseSettings;
  engine: EngineSettings;
  online_tools: OnlineToolsSettings;
  shortcuts: ShortcutSettings;
}

type SettingsTab = 'view' | 'scan' | 'database' | 'engine' | 'online' | 'shortcuts';

const SETTINGS_TABS: { key: SettingsTab; label: string }[] = [
  { key: 'view', label: 'View' },
  { key: 'scan', label: 'Scan' },
  { key: 'database', label: 'Database' },
  { key: 'engine', label: 'Engine' },
  { key: 'online', label: 'Online' },
  { key: 'shortcuts', label: 'Shortcuts' },
];

interface SettingsModalProps {
  open: boolean;
  onClose: () => void;
}

export default function SettingsModal({ open, onClose }: SettingsModalProps) {
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<SettingsTab>('view');

  const fetchSettings = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await invoke<AppSettings>('get_settings');
      setSettings(result);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (open) {
      fetchSettings();
    }
  }, [open, fetchSettings]);

  const saveSettings = async () => {
    if (!settings) return;
    setSaving(true);
    setError(null);
    try {
      await invoke('save_settings', { settings });
      onClose();
    } catch (e) {
      setError(String(e));
    } finally {
      setSaving(false);
    }
  };

  const updateSettings = (updater: (s: AppSettings) => AppSettings) => {
    setSettings((prev) => (prev ? updater(prev) : prev));
  };

  if (!open) return null;

  return (
    <div className="settings-modal-overlay" onClick={onClose}>
      <div className="settings-modal" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="settings-modal-header">
          <h2>Settings</h2>
          <button className="settings-close" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="settings-modal-body">
          {loading && <div>Loading settings...</div>}
          {error && <div className="settings-error">Error: {error}</div>}
          {!loading && settings && (
            <>
              {/* Tab bar */}
              <div className="settings-tabs">
                {SETTINGS_TABS.map((tab) => (
                  <button
                    key={tab.key}
                    className={`settings-tab ${activeTab === tab.key ? 'active' : ''}`}
                    onClick={() => setActiveTab(tab.key)}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              {/* Tab content */}
              <div className="settings-tab-content">
                {activeTab === 'view' && (
                  <div className="settings-section">
                    <label>
                      Theme:
                      <select
                        value={settings.view.theme}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            view: { ...s.view, theme: e.target.value },
                          }))
                        }
                      >
                        <option value="system">System</option>
                        <option value="light">Light</option>
                        <option value="dark">Dark</option>
                      </select>
                    </label>
                    <label>
                      Language:
                      <select
                        value={settings.view.language}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            view: { ...s.view, language: e.target.value },
                          }))
                        }
                      >
                        <option value="en">English</option>
                        <option value="zh-CN">中文</option>
                        <option value="ru">Русский</option>
                        <option value="de">Deutsch</option>
                        <option value="fr">Français</option>
                      </select>
                    </label>
                    <label>
                      <input
                        type="checkbox"
                        checked={settings.view.stay_on_top}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            view: { ...s.view, stay_on_top: e.target.checked },
                          }))
                        }
                      />
                      Stay on top
                    </label>
                    <label>
                      <input
                        type="checkbox"
                        checked={settings.view.advanced}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            view: { ...s.view, advanced: e.target.checked },
                          }))
                        }
                      />
                      Advanced mode
                    </label>
                  </div>
                )}

                {activeTab === 'scan' && (
                  <div className="settings-section">
                    <label>
                      <input
                        type="checkbox"
                        checked={settings.scan.scan_after_open}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            scan: { ...s.scan, scan_after_open: e.target.checked },
                          }))
                        }
                      />
                      Scan after open
                    </label>
                    <label>
                      <input
                        type="checkbox"
                        checked={settings.scan.hide_unknown}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            scan: { ...s.scan, hide_unknown: e.target.checked },
                          }))
                        }
                      />
                      Hide unknown
                    </label>
                    <label>
                      <input
                        type="checkbox"
                        checked={settings.scan.sort}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            scan: { ...s.scan, sort: e.target.checked },
                          }))
                        }
                      />
                      Sort results
                    </label>
                    <label>
                      <input
                        type="checkbox"
                        checked={settings.scan.log_profiling}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            scan: { ...s.scan, log_profiling: e.target.checked },
                          }))
                        }
                      />
                      Log profiling
                    </label>
                    <h4>Default Scan Flags</h4>
                    {Object.entries(settings.scan.flags).map(([key, value]) => (
                      <label key={key}>
                        <input
                          type="checkbox"
                          checked={value as boolean}
                          onChange={(e) =>
                            updateSettings((s) => ({
                              ...s,
                              scan: {
                                ...s.scan,
                                flags: {
                                  ...s.scan.flags,
                                  [key]: e.target.checked,
                                },
                              },
                            }))
                          }
                        />
                        {key.replace(/_/g, ' ')}
                      </label>
                    ))}
                  </div>
                )}

                {activeTab === 'database' && (
                  <div className="settings-section">
                    <label>
                      Main DB Path:
                      <input
                        type="text"
                        value={settings.database.main_path}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            database: { ...s.database, main_path: e.target.value },
                          }))
                        }
                      />
                    </label>
                    <label>
                      <input
                        type="checkbox"
                        checked={settings.database.extra_enabled}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            database: { ...s.database, extra_enabled: e.target.checked },
                          }))
                        }
                      />
                      Extra DB enabled
                    </label>
                    <label>
                      Extra DB Path:
                      <input
                        type="text"
                        value={settings.database.extra_path}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            database: { ...s.database, extra_path: e.target.value },
                          }))
                        }
                      />
                    </label>
                    <label>
                      <input
                        type="checkbox"
                        checked={settings.database.custom_enabled}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            database: { ...s.database, custom_enabled: e.target.checked },
                          }))
                        }
                      />
                      Custom DB enabled
                    </label>
                    <label>
                      Custom DB Path:
                      <input
                        type="text"
                        value={settings.database.custom_path}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            database: { ...s.database, custom_path: e.target.value },
                          }))
                        }
                      />
                    </label>
                  </div>
                )}

                {activeTab === 'engine' && (
                  <div className="settings-section">
                    <label>
                      <input
                        type="checkbox"
                        checked={settings.engine.die_enabled}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            engine: { ...s.engine, die_enabled: e.target.checked },
                          }))
                        }
                      />
                      DIE engine
                    </label>
                    {/* NFD engine removed: no backend exists (ADR 0035). */}
                    <label>
                      <input
                        type="checkbox"
                        checked={settings.engine.peid_enabled}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            engine: { ...s.engine, peid_enabled: e.target.checked },
                          }))
                        }
                      />
                      PEID engine
                    </label>
                    <label>
                      <input
                        type="checkbox"
                        checked={settings.engine.yara_enabled}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            engine: { ...s.engine, yara_enabled: e.target.checked },
                          }))
                        }
                      />
                      YARA engine
                    </label>
                  </div>
                )}

                {activeTab === 'online' && (
                  <div className="settings-section">
                    <label>
                      VirusTotal API key:
                      <input
                        type="password"
                        value={settings.online_tools?.virustotal_apikey ?? ''}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            online_tools: {
                              ...s.online_tools,
                              virustotal_apikey: e.target.value,
                            },
                          }))
                        }
                        placeholder="Leave empty to use browser jump mode"
                        className="w-full text-xs font-mono"
                      />
                    </label>
                    <p className="text-xs text-muted-foreground mt-1">
                      If empty, clicking VirusTotal opens the website with the
                      file's MD5 hash. If set, in-app scan results are shown
                      via the VirusTotal API v3.
                    </p>
                  </div>
                )}

                {activeTab === 'shortcuts' && (
                  <div className="settings-section">
                    {Object.entries(settings.shortcuts).map(([key, value]) => (
                      <label key={key}>
                        {key.replace(/_/g, ' ')}:
                        <input
                          type="text"
                          value={value}
                          onChange={(e) =>
                            updateSettings((s) => ({
                              ...s,
                              shortcuts: {
                                ...s.shortcuts,
                                [key]: e.target.value,
                              },
                            }))
                          }
                          placeholder="e.g. Ctrl+O"
                        />
                      </label>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="settings-modal-footer">
          <button onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button onClick={saveSettings} disabled={saving || !settings}>
            {saving ? 'Saving...' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}
