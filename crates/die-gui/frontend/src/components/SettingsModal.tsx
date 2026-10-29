import { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { X } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { SUPPORTED_LANGUAGES } from '../i18n/config';

// --- Settings types (mirror Rust AppSettings) ---

interface ViewSettings {
  theme: string;
  custom_theme?: string;
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
  archive_limits?: {
    members_normal?: number;
    members_aggressive?: number;
    single_member_bytes?: number;
    total_decompressed_bytes?: number;
    compression_ratio?: number;
    member_names?: number;
    member_string_bytes?: number;
    iso_max_depth?: number;
  } | null;
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

const SETTINGS_TABS: { key: SettingsTab; labelKey: string }[] = [
  { key: 'view', labelKey: 'settings.tabView' },
  { key: 'scan', labelKey: 'settings.tabScan' },
  { key: 'database', labelKey: 'settings.tabDatabase' },
  { key: 'engine', labelKey: 'settings.tabEngine' },
  { key: 'online', labelKey: 'settings.tabOnline' },
  { key: 'shortcuts', labelKey: 'settings.tabShortcuts' },
];

const BUILT_IN_THEMES = [
  'solarized-dark',
  'film-noir',
  'midnight-elegance',
  'lavender-dawn',
  'emerald-dusk',
  'cyber-noir',
];

interface SettingsModalProps {
  open: boolean;
  onClose: () => void;
}

export default function SettingsModal({ open, onClose }: SettingsModalProps) {
  const { t } = useTranslation();
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
          <h2>{t('settings.title')}</h2>
          <button className="settings-close" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="settings-modal-body">
          {loading && <div>{t('settings.loading')}</div>}
          {error && <div className="settings-error">{t('settings.error', { error })}</div>}
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
                    {t(tab.labelKey)}
                  </button>
                ))}
              </div>

              {/* Tab content */}
              <div className="settings-tab-content">
                {activeTab === 'view' && (
                  <div className="settings-section">
                    <label>
                      {t('settings.theme')}:
                      <select
                        value={settings.view.theme}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            view: { ...s.view, theme: e.target.value },
                          }))
                        }
                      >
                        <option value="system">{t('settings.system')}</option>
                        <option value="light">{t('settings.light')}</option>
                        <option value="dark">{t('settings.dark')}</option>
                        {BUILT_IN_THEMES.map((theme) => (
                          <option key={theme} value={theme}>
                            {theme.split('-').map((w) => w[0].toUpperCase() + w.slice(1)).join(' ')}
                          </option>
                        ))}
                        <option value="custom">{t('settings.themeCustom')}</option>
                      </select>
                    </label>
                    {settings.view.theme === 'custom' && (
                      <label>
                        {t('settings.customThemeVarsLabel')}
                        <textarea
                          rows={4}
                          className="w-full text-xs font-mono"
                          value={settings.view.custom_theme ?? ''}
                          onChange={(e) =>
                            updateSettings((s) => ({
                              ...s,
                              view: { ...s.view, custom_theme: e.target.value },
                            }))
                          }
                          placeholder="--fg-primary: 210 215 225"
                        />
                      </label>
                    )}
                    <label>
                      {t('settings.language')}:
                      <select
                        value={settings.view.language}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            view: { ...s.view, language: e.target.value },
                          }))
                        }
                      >
                        <option value="system">{t('settings.system')}</option>
                        {SUPPORTED_LANGUAGES.map((l) => (
                          <option key={l.code} value={l.code}>{l.name}</option>
                        ))}
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
                      {t('settings.stayOnTop')}
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
                      {t('settings.advancedMode')}
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
                      {t('settings.scanAfterOpen')}
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
                      {t('settings.hideUnknown')}
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
                      {t('settings.sortResults')}
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
                      {t('settings.logProfiling')}
                    </label>
                    <h4>{t('settings.defaultScanFlags')}</h4>
                    {Object.entries(settings.scan.flags).filter(([, value]) => typeof value === 'boolean').map(([key, value]) => (
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
                        {t(`settings.flag_${key}`, { defaultValue: key.replace(/_/g, ' ') })}
                      </label>
                    ))}
                  </div>
                )}

                {activeTab === 'database' && (
                  <div className="settings-section">
                    <label>
                      {t('settings.mainDbPath')}:
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
                      {t('settings.extraDbEnabled')}
                    </label>
                    <label>
                      {t('settings.extraDbPath')}:
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
                      {t('settings.customDbEnabled')}
                    </label>
                    <label>
                      {t('settings.customDbPath')}:
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
                      {t('settings.engineDie')}
                    </label>
                    <label>
                      <input
                        type="checkbox"
                        checked={settings.engine.nfd_enabled}
                        onChange={(e) =>
                          updateSettings((s) => ({
                            ...s,
                            engine: { ...s.engine, nfd_enabled: e.target.checked },
                          }))
                        }
                      />
                      {t('settings.engineNfd')}
                    </label>
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
                      {t('settings.enginePeid')}
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
                      {t('settings.engineYara')}
                    </label>
                  </div>
                )}

                {activeTab === 'online' && (
                  <div className="settings-section">
                    <label>
                      {t('settings.vtApiKey')}:
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
                        placeholder={t('settings.vtApiKeyPlaceholder')}
                        className="w-full text-xs font-mono"
                      />
                    </label>
                    <p className="text-xs text-muted-foreground mt-1">
                      {t('settings.vtApiKeyHelp')}
                    </p>
                  </div>
                )}

                {activeTab === 'shortcuts' && (
                  <div className="settings-section">
                    {Object.entries(settings.shortcuts).map(([key, value]) => (
                      <label key={key}>
                        {t(`settings.shortcut_${key}`, { defaultValue: key.replace(/_/g, ' ') })}:
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
                          placeholder={t('settings.shortcutPlaceholder')}
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
            {t('settings.cancel')}
          </button>
          <button onClick={saveSettings} disabled={saving || !settings}>
            {saving ? t('settings.saving') : t('settings.save')}
          </button>
        </div>
      </div>
    </div>
  );
}
