import i18n from "i18next";
import { initReactI18next } from "react-i18next";

import en from "./locales/en.json";
import zhCN from "./locales/zh-CN.json";
import ru from "./locales/ru.json";
import de from "./locales/de.json";
import fr from "./locales/fr.json";
import ar from "./locales/ar.json";
import bn from "./locales/bn.json";
import es from "./locales/es.json";
import fa from "./locales/fa.json";
import he from "./locales/he.json";
import hiIN from "./locales/hi-IN.json";
import id from "./locales/id.json";
import it from "./locales/it.json";
import ja from "./locales/ja.json";
import ko from "./locales/ko.json";
import pl from "./locales/pl.json";
import ptBR from "./locales/pt-BR.json";
import ptPT from "./locales/pt-PT.json";
import sq from "./locales/sq.json";
import sv from "./locales/sv.json";
import tr from "./locales/tr.json";
import uk from "./locales/uk.json";
import vi from "./locales/vi.json";
import zhTW from "./locales/zh-TW.json";

/**
 * Locale codes available in the settings dropdown. Native names are
 * shown as-is so users can find their language without knowing English.
 * All catalogs except en/zh-CN/ru/de/fr are terminology-anchored drafts
 * (see tools/i18n/gen_locales.py and <code>.draft.json manifests).
 */
export const SUPPORTED_LANGUAGES: { code: string; name: string }[] = [
  { code: "en", name: "English" },
  { code: "zh-CN", name: "中文（简体）" },
  { code: "ru", name: "Русский" },
  { code: "de", name: "Deutsch" },
  { code: "fr", name: "Français" },
  { code: "es", name: "Español" },
  { code: "it", name: "Italiano" },
  { code: "pt-BR", name: "Português (Brasil)" },
  { code: "pt-PT", name: "Português" },
  { code: "pl", name: "Polski" },
  { code: "uk", name: "Українська" },
  { code: "tr", name: "Türkçe" },
  { code: "sv", name: "Svenska" },
  { code: "sq", name: "Shqip" },
  { code: "vi", name: "Tiếng Việt" },
  { code: "id", name: "Bahasa Indonesia" },
  { code: "ja", name: "日本語" },
  { code: "ko", name: "한국어" },
  { code: "zh-TW", name: "中文（繁體）" },
  { code: "hi-IN", name: "हिन्दी" },
  { code: "bn", name: "বাংলা" },
  { code: "ar", name: "العربية" },
  { code: "he", name: "עברית" },
  { code: "fa", name: "فارسی" },
];

i18n.use(initReactI18next).init({
  resources: {
    en: { translation: en },
    "zh-CN": { translation: zhCN },
    ru: { translation: ru },
    de: { translation: de },
    fr: { translation: fr },
    ar: { translation: ar },
    bn: { translation: bn },
    es: { translation: es },
    fa: { translation: fa },
    he: { translation: he },
    "hi-IN": { translation: hiIN },
    id: { translation: id },
    it: { translation: it },
    ja: { translation: ja },
    ko: { translation: ko },
    pl: { translation: pl },
    "pt-BR": { translation: ptBR },
    "pt-PT": { translation: ptPT },
    sq: { translation: sq },
    sv: { translation: sv },
    tr: { translation: tr },
    uk: { translation: uk },
    vi: { translation: vi },
    "zh-TW": { translation: zhTW },
  },
  lng: "en",
  fallbackLng: "en",
  interpolation: { escapeValue: false },
});

/** Apply the text direction of the active language to the document
 * (RTL for ar/he/fa). i18next resolves direction per language. */
const applyDir = (lng: string | undefined) => {
  if (lng) {
    document.documentElement.dir = i18n.dir(lng);
  }
};
applyDir(i18n.language);
i18n.on("languageChanged", applyDir);

export default i18n;
