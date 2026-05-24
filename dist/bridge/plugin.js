/**
 * @fileoverview FETIH Plugin Sistemi — v3.9.5
 * AGPL-3.0
 * AGPL-3.0
 */
import { existsSync, readFileSync, readdirSync, mkdirSync, writeFileSync, watch } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { createHash } from 'crypto';
import { pathToFileURL } from 'url';
// ---------------------------------------------------------------------------
// Sabitler
// ---------------------------------------------------------------------------
const PLUGIN_DIR = join(homedir(), '.fetih', 'plugins');
const REGISTRY_FILE = join(PLUGIN_DIR, 'registry.json');
const ALL_PERMISSIONS = new Set(['read_fs', 'write_fs', 'network', 'exec', 'audio', 'video']);
const PROFILE_PERMISSIONS = {
    safe: new Set(['read_fs']),
    standard: new Set(['read_fs', 'write_fs']),
    pentest: new Set(['read_fs', 'write_fs', 'network', 'exec']),
};
// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
let registry = null;
// ---------------------------------------------------------------------------
// Yardımcılar
// ---------------------------------------------------------------------------
function sha256File(filePath) {
    return createHash('sha256').update(readFileSync(filePath)).digest('hex');
}
function log(msg) {
    process.stderr.write(`[fetih:plugin] ${msg}\n`);
}
// ---------------------------------------------------------------------------
// Plugin Registry Yönetimi
// ---------------------------------------------------------------------------
export function getPluginDir() {
    if (!existsSync(PLUGIN_DIR)) {
        mkdirSync(PLUGIN_DIR, { recursive: true });
    }
    return PLUGIN_DIR;
}
export function getRegistryState() {
    if (registry)
        return registry;
    registry = { plugins: new Map() };
    if (existsSync(REGISTRY_FILE)) {
        try {
            const raw = JSON.parse(readFileSync(REGISTRY_FILE, 'utf-8'));
            if (Array.isArray(raw.plugins)) {
                for (const p of raw.plugins) {
                    registry.plugins.set(p.name, p);
                }
            }
        }
        catch { /* ignore */ }
    }
    return registry;
}
function saveRegistryState() {
    if (!registry)
        return;
    const data = {
        plugins: Array.from(registry.plugins.values()).map(p => ({
            ...p,
            loadedAt: p.loadedAt?.toISOString(),
        })),
    };
    writeFileSync(REGISTRY_FILE, JSON.stringify(data, null, 2), 'utf-8');
}
// ---------------------------------------------------------------------------
// Manifest Okuma
// ---------------------------------------------------------------------------
function parseManifest(manifestPath) {
    const raw = JSON.parse(readFileSync(manifestPath, 'utf-8'));
    if (!raw.name || typeof raw.name !== 'string')
        throw new Error('manifest.name zorunlu');
    if (!raw.main || typeof raw.main !== 'string')
        throw new Error('manifest.main zorunlu');
    if (!Array.isArray(raw.permissions))
        throw new Error('manifest.permissions dizi olmalı');
    if (!raw.sha256 || typeof raw.sha256 !== 'string')
        throw new Error('manifest.sha256 zorunlu');
    const invalidPerm = raw.permissions.find(p => !ALL_PERMISSIONS.has(p));
    if (invalidPerm)
        throw new Error(`Geçersiz izin: ${invalidPerm}`);
    return {
        name: raw.name,
        version: raw.version || '1.0.0',
        description: raw.description || '',
        main: raw.main,
        permissions: raw.permissions,
        sha256: raw.sha256.toLowerCase(),
        author: raw.author,
        type: raw.type || 'tool',
    };
}
// ---------------------------------------------------------------------------
// Plugin Keşfi
// ---------------------------------------------------------------------------
export function discoverPlugins() {
    const dir = getPluginDir();
    return readdirSync(dir)
        .filter(f => f.endsWith('.js') || f.endsWith('.mjs'))
        .sort();
}
// ---------------------------------------------------------------------------
// Plugin Yükleme
// ---------------------------------------------------------------------------
export async function loadPlugin(fileName, config) {
    const pluginDir = getPluginDir();
    const pluginPath = join(pluginDir, fileName);
    const baseName = fileName.replace(/\.(js|mjs)$/, '');
    const manifestPath = join(pluginDir, `${baseName}.manifest.json`);
    if (!existsSync(manifestPath)) {
        log(`${fileName} — manifest dosyası yok (${baseName}.manifest.json)`);
        return null;
    }
    let manifest;
    try {
        manifest = parseManifest(manifestPath);
    }
    catch (err) {
        log(`${fileName} — manifest geçersiz: ${err}`);
        return null;
    }
    if (manifest.main !== fileName) {
        log(`${fileName} — manifest.main eşleşmiyor (${manifest.main})`);
        return null;
    }
    // Güvenlik profili kontrolü
    const profile = config?.tools?.securityProfile ?? 'standard';
    const allowedPerms = PROFILE_PERMISSIONS[profile];
    const disallowed = manifest.permissions.find(p => !allowedPerms.has(p));
    if (disallowed) {
        log(`${fileName} — "${profile}" profilinde "${disallowed}" izni yok`);
        return null;
    }
    // SHA256 doğrulama
    const actualHash = sha256File(pluginPath);
    if (actualHash !== manifest.sha256) {
        log(`${fileName} — SHA256 uyuşmazlığı (dosya değişmiş olabilir)`);
        return null;
    }
    // Plugin yükle
    try {
        const module = await import(pathToFileURL(pluginPath).href);
        const tool = module.default;
        if (!tool || typeof tool.execute !== 'function' || typeof tool.name !== 'string') {
            log(`${fileName} — default export geçerli bir ToolDefinition değil`);
            return null;
        }
        if (tool.name !== manifest.name) {
            log(`${fileName} — araç adı manifest ile uyuşmuyor`);
            return null;
        }
        // Registry'e kaydet
        const state = getRegistryState();
        state.plugins.set(manifest.name, {
            manifest,
            dir: pluginDir,
            enabled: true,
            loadedAt: new Date(),
        });
        saveRegistryState();
        log(`${manifest.name} v${manifest.version} yüklendi ✅`);
        return tool;
    }
    catch (err) {
        log(`${fileName} — yükleme hatası: ${err}`);
        const state = getRegistryState();
        state.plugins.set(manifest.name, {
            manifest,
            dir: pluginDir,
            enabled: false,
            loadError: String(err),
        });
        saveRegistryState();
        return null;
    }
}
// ---------------------------------------------------------------------------
// Toplu Plugin Yükleme
// ---------------------------------------------------------------------------
export async function loadAllPlugins(config) {
    const files = discoverPlugins();
    const loadPromises = files.map(file => loadPlugin(file, config));
    const results = await Promise.all(loadPromises);
    const tools = results.filter((tool) => tool !== null);
    log(`Toplam ${tools.length}/${files.length} plugin yüklendi`);
    return tools;
}
// ---------------------------------------------------------------------------
// Plugin Yönetim Araçları
// ---------------------------------------------------------------------------
export function listPlugins() {
    return Array.from(getRegistryState().plugins.values());
}
export function getPlugin(name) {
    return getRegistryState().plugins.get(name);
}
export function enablePlugin(name) {
    const state = getRegistryState();
    const plugin = state.plugins.get(name);
    if (!plugin)
        return false;
    plugin.enabled = true;
    saveRegistryState();
    return true;
}
export function disablePlugin(name) {
    const state = getRegistryState();
    const plugin = state.plugins.get(name);
    if (!plugin)
        return false;
    plugin.enabled = false;
    saveRegistryState();
    return true;
}
export function removePlugin(name) {
    const state = getRegistryState();
    const existed = state.plugins.delete(name);
    if (existed)
        saveRegistryState();
    return existed;
}
// ---------------------------------------------------------------------------
// Hot-Reload (Geliştirme modu)
// ---------------------------------------------------------------------------
let watcher = null;
export function watchPluginDir(onPluginChange) {
    if (watcher)
        return;
    const dir = getPluginDir();
    watcher = watch(dir, async (eventType, fileName) => {
        if (!fileName)
            return;
        if (fileName.endsWith('.js') || fileName.endsWith('.mjs')) {
            log(`Değişiklik algılandı: ${fileName} (${eventType})`);
            if (eventType === 'change') {
                // Plugin güncellendi — yeniden yükle
                const baseName = fileName.replace(/\.(js|mjs)$/, '');
                // Eski kaydı temizle
                const pluginName = baseName;
                const state = getRegistryState();
                state.plugins.delete(pluginName);
                // Yeniden yükle
                const tool = await loadPlugin(fileName);
                if (tool && onPluginChange) {
                    onPluginChange(tool.name, 'loaded');
                }
            }
            else if (eventType === 'rename') {
                log(`Plugin dosyası silindi/taşındı: ${fileName}`);
                if (onPluginChange) {
                    const baseName = fileName.replace(/\.(js|mjs)$/, '');
                    onPluginChange(baseName, 'removed');
                }
            }
        }
    });
    log(`Plugin dizini izleniyor: ${dir}`);
}
export function stopWatching() {
    if (watcher) {
        watcher.close();
        watcher = null;
        log('Plugin izleme durduruldu');
    }
}
// ---------------------------------------------------------------------------
// İnisiyalizasyon
// ---------------------------------------------------------------------------
export async function initPluginSystem(config) {
    getRegistryState();
    return loadAllPlugins(config);
}
