import { createHash, randomUUID } from 'node:crypto';
import { homedir } from 'node:os';
import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { chmod, lstat, mkdir, open, readFile, readdir, rename, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { unzipSync } from 'fflate';
import { product } from './product.js';

/** npm links bin entries on Unix; resolve the link without auto-starting imported modules. */
export function isMainModule(moduleUrl: string): boolean {
  if (!process.argv[1]) return false;
  try {
    return moduleUrl === pathToFileURL(realpathSync(process.argv[1])).href;
  } catch {
    return false;
  }
}

export class ClientError extends Error {
  constructor(
    message: string,
    public code = 'client_error',
    public retryAfter?: number,
  ) {
    super(message);
  }
}
export const DEFAULT_URL = product.apiOrigin ?? 'http://127.0.0.1:4310';
const loopback = (url: URL) => ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
export function normalizeServiceUrl(input = (product.siteId ? undefined : process.env.SKILLHARBOR_URL) || DEFAULT_URL): string {
  const url = new URL(input);
  if (
    (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback(url))) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== '/' ||
    (product.siteId && url.origin !== product.apiOrigin && !loopback(url))
  )
    throw new ClientError('服务地址必须是无凭据、无路径的 HTTP(S) 源地址。');
  return url.origin;
}
export function validateSlug(slug: string): string {
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(slug)) throw new ClientError('无效的 Skill 标识。');
  return slug;
}
function configRoot(): string {
  return path.resolve(
    process.env.SKILLHARBOR_CONFIG_DIR ||
      (process.platform === 'win32'
        ? path.join(process.env.APPDATA || homedir(), 'SkillHarbor')
        : path.join(process.env.XDG_CONFIG_HOME || path.join(homedir(), '.config'), 'skillharbor')),
  );
}
function credentialPath(baseUrl: string): string {
  return path.join(
    configRoot(),
    'credentials',
    createHash('sha256').update(baseUrl).digest('hex') + '.json',
  );
}
/** DPAPI binds the encrypted credential to the current Windows user. Secret data goes via stdin, never arguments. */
async function windowsProtect(value: string, decrypt = false): Promise<string> {
  const operation = decrypt
    ? '$bytes = [Convert]::FromBase64String($value); $plain = [Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser); [Console]::Out.Write([Text.Encoding]::UTF8.GetString($plain)); [Array]::Clear($plain, 0, $plain.Length)'
    : '$bytes = [Text.Encoding]::UTF8.GetBytes($value); $protected = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser); [Console]::Out.Write([Convert]::ToBase64String($protected)); [Array]::Clear($bytes, 0, $bytes.Length)';
  const script =
    '$ErrorActionPreference = "Stop"; Add-Type -AssemblyName System.Security; $value = [Console]::In.ReadToEnd(); ' +
    operation;
  return new Promise((resolve, reject) => {
    const child = spawn(
      'powershell.exe',
      [
        '-NoProfile',
        '-NonInteractive',
        '-EncodedCommand',
        Buffer.from(script, 'utf16le').toString('base64'),
      ],
      { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] },
    );
    const chunks: Buffer[] = [];
    let size = 0;
    const timer = setTimeout(() => {
      child.kill();
      reject(new ClientError('Windows 凭据保护超时。'));
    }, 15_000);
    child.stdout.on('data', (chunk) => {
      size += chunk.length;
      if (size > 16_384) child.kill();
      else chunks.push(chunk);
    });
    child.stderr.resume();
    child.once('error', () => {
      clearTimeout(timer);
      reject(new ClientError('无法使用 Windows DPAPI 保护本机凭据。'));
    });
    child.once('close', (code) => {
      clearTimeout(timer);
      if (code === 0 && size <= 16_384) resolve(Buffer.concat(chunks).toString('utf8'));
      else reject(new ClientError('Windows 凭据保护失败，请重新登录。'));
    });
    child.stdin.on('error', () => {});
    child.stdin.end(value);
  });
}
export async function readCredential(baseUrl: string): Promise<string | null> {
  const filename = credentialPath(baseUrl);
  try {
    const info = await lstat(filename);
    if (!info.isFile() || info.isSymbolicLink() || info.size > 8192)
      throw new ClientError('凭据文件类型或大小无效。');
    if (process.platform !== 'win32' && info.mode & 0o077)
      throw new ClientError('凭据文件权限必须为 0600。');
    const data = JSON.parse(await readFile(filename, 'utf8'));
    if (data.origin !== baseUrl) return null;
    if (process.platform === 'win32') {
      if (data.protection !== 'windows-dpapi' || typeof data.protectedToken !== 'string')
        throw new ClientError('凭据不是 Windows 用户加密格式，请重新登录。');
      return windowsProtect(data.protectedToken, true);
    }
    return typeof data.token === 'string' ? data.token : null;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
}
async function writePrivateJson(filename: string, data: unknown): Promise<void> {
  await mkdir(path.dirname(filename), { recursive: true, mode: 0o700 });
  const existing = await lstat(filename).catch(() => null);
  if (existing?.isSymbolicLink()) throw new ClientError('不能写入符号链接。');
  const temp = filename + '.' + randomUUID() + '.tmp';
  const handle = await open(temp, 'wx', 0o600);
  try {
    await handle.writeFile(JSON.stringify(data, null, 2));
  } finally {
    await handle.close();
  }
  try {
    await rename(temp, filename);
  } catch (error) {
    await rm(temp, { force: true });
    throw error;
  }
  if (process.platform !== 'win32') await chmod(filename, 0o600);
}
export async function saveCredential(
  baseUrl: string,
  token: string,
  expiresAt: string,
): Promise<void> {
  await writePrivateJson(
    credentialPath(baseUrl),
    process.platform === 'win32'
      ? {
          origin: baseUrl,
          protection: 'windows-dpapi',
          protectedToken: await windowsProtect(token),
          expiresAt,
        }
      : { origin: baseUrl, token, expiresAt },
  );
}
export async function deleteCredential(baseUrl: string): Promise<void> {
  await rm(credentialPath(baseUrl), { force: true });
}

export interface DeviceFlow {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  expiresIn: number;
  interval: number;
  startedAt: number;
  nextPollAt: number;
}
export interface SkillSummary {
  slug: string;
  name: string;
  description: string;
  version: string;
  category?: string;
  tags?: string[];
  [key: string]: unknown;
}
export class SkillHarborClient {
  readonly baseUrl: string;
  constructor(
    baseUrl?: string,
    public token?: string,
  ) {
    this.baseUrl = normalizeServiceUrl(baseUrl);
  }
  async request<T = any>(
    endpoint: string,
    body?: unknown,
    authenticated = true,
    method?: string,
  ): Promise<T> {
    const token = authenticated ? this.token || (await readCredential(this.baseUrl)) : null;
    if (authenticated && !token)
      throw new ClientError('请先使用 login 连接账户。', 'authentication_required');
    const response = await fetch(this.baseUrl + endpoint, {
      method: method || (body === undefined ? 'GET' : 'POST'),
      redirect: 'error',
      signal: AbortSignal.timeout(30_000),
      headers: {
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    if (!response.ok) return this.fail(response);
    return (await response.json()) as T;
  }
  async fail(response: Response): Promise<never> {
    const data = (await response.json().catch(() => ({}))) as any;
    const retry = Number(response.headers.get('retry-after') || data.error?.retryAfter);
    throw new ClientError(
      typeof data.error?.message === 'string'
        ? data.error.message
        : `服务返回 HTTP ${response.status}`,
      data.error?.code || `http_${response.status}`,
      Number.isFinite(retry) ? retry : undefined,
    );
  }
  async startDevice(): Promise<DeviceFlow> {
    const data = await this.request<any>('/api/auth/device/code', {}, false);
    if (
      typeof data.deviceCode !== 'string' ||
      typeof data.userCode !== 'string' ||
      !/^[A-F0-9]{8}$/.test(data.userCode) ||
      !Number.isInteger(data.expiresIn) || data.expiresIn < 1 || data.expiresIn > 900 ||
      !Number.isInteger(data.interval) || data.interval < 1 || data.interval > 60 ||
      typeof data.verificationUri !== 'string'
    )
      throw new ClientError('设备授权响应无效。');
    const url = new URL(data.verificationUri);
    if (url.username || url.password || url.hash ||
        (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback(url))) ||
        (product.siteId && this.baseUrl === product.apiOrigin && (
          data.siteId !== product.siteId || url.origin !== product.websiteOrigin ||
          url.pathname !== '/skillharbor/authorize' || url.searchParams.get('user_code') !== data.userCode
        )) || (product.siteId && this.baseUrl !== product.apiOrigin && !loopback(url)))
      throw new ClientError('设备确认地址无效。');
    const interval = data.interval as number;
    return { ...data, interval, startedAt: Date.now(), nextPollAt: Date.now() + interval * 1000 };
  }
  async pollDevice(
    flow: DeviceFlow,
  ): Promise<{ status: 'pending' | 'connected'; expiresAt?: string; pollAfterSeconds?: number }> {
    if (Date.now() > flow.startedAt + flow.expiresIn * 1000)
      throw new ClientError('设备码已过期，请重新连接。', 'expired_token');
    if (Date.now() < flow.nextPollAt)
      return {
        status: 'pending',
        pollAfterSeconds: Math.ceil((flow.nextPollAt - Date.now()) / 1000),
      };
    flow.nextPollAt = Date.now() + flow.interval * 1000;
    try {
      const data = await this.request<any>(
        '/api/auth/device/token',
        { deviceCode: flow.deviceCode },
        false,
      );
      if (typeof data.accessToken !== 'string' || typeof data.expiresAt !== 'string')
        throw new ClientError('授权响应无效。');
      await saveCredential(this.baseUrl, data.accessToken, data.expiresAt);
      return { status: 'connected', expiresAt: data.expiresAt };
    } catch (error) {
      if (error instanceof ClientError && error.code === 'authorization_pending')
        return { status: 'pending', pollAfterSeconds: flow.interval };
      if (error instanceof ClientError && error.code === 'slow_down') {
        flow.interval += 5;
        flow.nextPollAt = Date.now() + flow.interval * 1000;
        return { status: 'pending', pollAfterSeconds: flow.interval };
      }
      throw error;
    }
  }
  async logout(): Promise<{ serverRevoked: boolean }> {
    let serverRevoked = false;
    try {
      await this.request('/api/auth/logout', {});
      serverRevoked = true;
    } finally {
      await deleteCredential(this.baseUrl);
    }
    return { serverRevoked };
  }
  async download(slug: string, expectedVersion?: string): Promise<VerifiedArchive> {
    validateSlug(slug);
    const token = this.token || (await readCredential(this.baseUrl));
    if (!token) throw new ClientError('请先连接账户。', 'authentication_required');
    const response = await fetch(
      `${this.baseUrl}/api/skills/${slug}/download${expectedVersion ? '?version=' + encodeURIComponent(expectedVersion) : ''}`,
      {
        redirect: 'error',
        signal: AbortSignal.timeout(60_000),
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/zip' },
      },
    );
    if (!response.ok) return this.fail(response);
    const length = Number(response.headers.get('content-length'));
    if (!Number.isSafeInteger(length) || length <= 0 || length > MAX_ARCHIVE_BYTES)
      throw new ClientError('包大小无效或超过 32 MiB。');
    if (response.headers.get('content-type')?.split(';')[0] !== 'application/zip')
      throw new ClientError('响应不是 ZIP。');
    const version = response.headers.get('x-skill-version');
    if (
      response.headers.get('x-skill-slug') !== slug ||
      !version ||
      version.length > 64 ||
      (expectedVersion && version !== expectedVersion)
    )
      throw new ClientError('下载标识或版本与选择不一致。');
    const expectedHash = response.headers.get('x-archive-sha256') || '';
    const chunks: Uint8Array[] = [];
    let total = 0;
    if (!response.body) throw new ClientError('下载内容为空。');
    const reader = response.body.getReader();
    while (true) {
      const part = await reader.read();
      if (part.done) break;
      total += part.value.byteLength;
      if (total > length || total > MAX_ARCHIVE_BYTES) {
        await reader.cancel();
        throw new ClientError('下载内容超过声明大小。');
      }
      chunks.push(part.value);
    }
    if (total !== length) throw new ClientError('下载内容长度校验失败。');
    const bytes = Buffer.concat(chunks);
    return verifyArchive(bytes, expectedHash, slug, version);
  }
}
export async function openBrowser(url: string): Promise<boolean> {
  const parsed = new URL(url);
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new ClientError('浏览器地址无效。');
  const command =
    process.platform === 'win32'
      ? 'rundll32.exe'
      : process.platform === 'darwin'
        ? 'open'
        : 'xdg-open';
  const args =
    process.platform === 'win32'
      ? ['url.dll,FileProtocolHandler', parsed.toString()]
      : [parsed.toString()];
  return new Promise((resolve) => {
    const child = spawn(command, args, { detached: true, stdio: 'ignore', windowsHide: true });
    child.once('error', () => resolve(false));
    child.once('spawn', () => {
      child.unref();
      resolve(true);
    });
  });
}

export const MAX_ARCHIVE_BYTES = 32 * 1024 * 1024;
const MAX_UNPACKED = 64 * 1024 * 1024;
const MAX_FILES = 512;
export interface VerifiedArchive {
  slug: string;
  version: string;
  sha256: string;
  bytes: Uint8Array;
  files: { path: string; data: Uint8Array }[];
}
export function safeRelativePath(value: string): string {
  if (
    !value ||
    value.length > 512 ||
    value.includes('\\') ||
    value.includes(':') ||
    value.includes('\0') ||
    value.startsWith('/') ||
    /[\x00-\x1f]/.test(value)
  )
    throw new ClientError('包内存在不安全的路径。');
  const parts = value.replace(/\/$/, '').split('/');
  if (
    parts.some(
      (part) =>
        !part ||
        part === '.' ||
        part === '..' ||
        /[. ]$/.test(part) ||
        /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part),
    )
  )
    throw new ClientError('包内存在不安全的文件名。');
  return parts.join('/');
}
/** Inspect central directory BEFORE allocating uncompressed files. ZIP64/encrypted/symlink archives are rejected. */
export function inspectSkillArchive(
  bytes: Uint8Array,
  slug: string,
): { path: string; data: Uint8Array }[] {
  validateSlug(slug);
  if (bytes.byteLength > MAX_ARCHIVE_BYTES || bytes.byteLength < 22)
    throw new ClientError('ZIP 大小无效。');
  const buffer = Buffer.from(bytes);
  let eocd = -1;
  for (let i = buffer.length - 22; i >= Math.max(0, buffer.length - 65557); i--)
    if (
      buffer.readUInt32LE(i) === 0x06054b50 &&
      i + 22 + buffer.readUInt16LE(i + 20) === buffer.length
    ) {
      eocd = i;
      break;
    }
  if (eocd < 0 || buffer.readUInt16LE(eocd + 4) !== 0 || buffer.readUInt16LE(eocd + 6) !== 0)
    throw new ClientError('不支持该 ZIP 格式。');
  const count = buffer.readUInt16LE(eocd + 10),
    centralSize = buffer.readUInt32LE(eocd + 12),
    centralStart = buffer.readUInt32LE(eocd + 16);
  if (
    !count ||
    count > MAX_FILES ||
    count === 0xffff ||
    centralStart + centralSize !== eocd ||
    buffer.readUInt16LE(eocd + 8) !== count
  )
    throw new ClientError('ZIP 目录或文件数量无效。');
  let pos = centralStart,
    totalSize = 0;
  const names = new Set<string>();
  const expected = new Map<string, number>();
  for (let i = 0; i < count; i++) {
    if (pos + 46 > eocd || buffer.readUInt32LE(pos) !== 0x02014b50)
      throw new ClientError('ZIP 目录损坏。');
    const flags = buffer.readUInt16LE(pos + 8),
      method = buffer.readUInt16LE(pos + 10),
      compressedSize = buffer.readUInt32LE(pos + 20),
      size = buffer.readUInt32LE(pos + 24),
      nameLength = buffer.readUInt16LE(pos + 28),
      extraLength = buffer.readUInt16LE(pos + 30),
      commentLength = buffer.readUInt16LE(pos + 32),
      external = buffer.readUInt32LE(pos + 38),
      localOffset = buffer.readUInt32LE(pos + 42);
    const end = pos + 46 + nameLength + extraLength + commentLength;
    if (
      end > eocd ||
      flags & 1 ||
      ![0, 8].includes(method) ||
      ((external >>> 16) & 0xf000) === 0xa000 ||
      size === 0xffffffff ||
      compressedSize === 0xffffffff
    )
      throw new ClientError('ZIP 含加密、链接或不支持的条目。');
    const name = buffer.subarray(pos + 46, pos + 46 + nameLength).toString('utf8');
    const normalized = safeRelativePath(name),
      key = normalized.toLowerCase();
    if (
      !(normalized.startsWith(slug + '/') || (normalized === slug && name.endsWith('/'))) ||
      names.has(key)
    )
      throw new ClientError('包根目录不匹配或存在重复文件名。');
    names.add(key);
    if (localOffset + 30 > centralStart || buffer.readUInt32LE(localOffset) !== 0x04034b50)
      throw new ClientError('ZIP 本地目录损坏。');
    const localNameLength = buffer.readUInt16LE(localOffset + 26),
      localExtra = buffer.readUInt16LE(localOffset + 28);
    if (
      buffer.subarray(localOffset + 30, localOffset + 30 + localNameLength).toString('utf8') !==
        name ||
      localOffset + 30 + localNameLength + localExtra + compressedSize > centralStart
    )
      throw new ClientError('ZIP 文件目录不一致。');
    totalSize += size;
    if (totalSize > MAX_UNPACKED || size > MAX_ARCHIVE_BYTES)
      throw new ClientError('解压大小超过限制。');
    if (!name.endsWith('/')) expected.set(name, size);
    pos = end;
  }
  if (pos !== eocd) throw new ClientError('ZIP 目录长度错误。');
  for (const name of names) {
    const segments = name.split('/');
    for (let i = 1; i < segments.length; i++) {
      const parent = segments.slice(0, i).join('/');
      if ([...expected.keys()].some((n) => n.toLowerCase() === parent))
        throw new ClientError('ZIP 存在文件与目录冲突。');
    }
  }
  const unpacked = unzipSync(bytes, {
    filter: (file) => expected.has(file.name) && file.originalSize <= MAX_ARCHIVE_BYTES,
  });
  const files = Object.entries(unpacked).map(([name, data]) => {
    if (expected.get(name) !== data.length) throw new ClientError('ZIP 文件大小不匹配。');
    return { path: name.slice(slug.length + 1), data };
  });
  if (
    files.length !== expected.size ||
    !files.some((file) => file.path === 'SKILL.md' && file.data.length > 0)
  )
    throw new ClientError('包中缺少有效的 SKILL.md。');
  return files;
}
export function verifyArchive(
  bytes: Uint8Array,
  expectedHash: string,
  slug: string,
  version: string,
): VerifiedArchive {
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  if (!/^[a-f0-9]{64}$/i.test(expectedHash) || sha256 !== expectedHash.toLowerCase())
    throw new ClientError('SHA-256 完整性校验失败。');
  return { slug, version, sha256, bytes, files: inspectSkillArchive(bytes, slug) };
}

export function skillsDirectory(agent = 'shared', target?: string): string {
  if (target) return path.resolve(target);
  if (!['shared', 'codex', 'cursor', 'claude-code'].includes(agent))
    throw new ClientError('不支持的 Agent。可选 shared、codex、cursor、claude-code。');
  return path.join(homedir(), agent === 'claude-code' ? '.claude' : '.agents', 'skills');
}
export interface InstallReceipt {
  slug: string;
  version: string;
  origin: string;
  sha256: string;
  installedAt: string;
  targetPath: string;
}
export async function listInstalled(directory: string, origin: string): Promise<InstallReceipt[]> {
  const folder = path.join(path.resolve(directory), '.skillharbor', 'installs');
  const names = await readdir(folder).catch((error: NodeJS.ErrnoException) => {
    if (error.code === 'ENOENT') return [];
    throw error;
  });
  const receipts: InstallReceipt[] = [];
  for (const name of names) {
    if (!/^[a-z0-9][a-z0-9-]{0,63}\.json$/.test(name)) continue;
    const filename = path.join(folder, name);
    const info = await lstat(filename);
    if (!info.isFile() || info.size > 8192) continue;
    const data = JSON.parse(await readFile(filename, 'utf8')) as InstallReceipt;
    if (
      data.origin === origin &&
      data.slug + '.json' === name &&
      data.targetPath === path.join(path.resolve(directory), data.slug) &&
      (await lstat(path.join(data.targetPath, 'SKILL.md'))
        .then((s) => s.isFile())
        .catch(() => false))
    )
      receipts.push(data);
  }
  return receipts;
}
async function assertNoSymlinkAncestors(value: string): Promise<void> {
  let current = path.resolve(value);
  for (;;) {
    const info = await lstat(current).catch((error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') return null;
      throw error;
    });
    if (info?.isSymbolicLink()) throw new ClientError('安装目录不能经过符号链接。');
    const parent = path.dirname(current);
    if (parent === current) return;
    current = parent;
  }
}
export async function installSkill(
  client: SkillHarborClient,
  slug: string,
  directory: string,
  options: { update?: boolean; expectedVersion?: string } = {},
): Promise<{ targetPath: string; version: string; backupPath?: string }> {
  validateSlug(slug);
  directory = path.resolve(directory);
  const lockDirectory = path.join(directory, '.skillharbor', 'locks');
  await assertNoSymlinkAncestors(lockDirectory);
  await mkdir(lockDirectory, { recursive: true, mode: 0o700 });
  const lockPath = path.join(lockDirectory, slug + '.lock');
  let lock;
  try {
    lock = await open(lockPath, 'wx', 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'EEXIST')
      throw new ClientError(
        '该 Skill 正在安装或更新。若上次进程异常退出，请确认没有安装进程后移除对应 .skillharbor/locks/*.lock 文件。',
        'installation_locked',
      );
    throw error;
  }
  try {
    await lock.writeFile(JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }));
    await lock.close();
    return await installSkillUnlocked(client, slug, directory, options);
  } finally {
    await lock.close().catch(() => {});
    await rm(lockPath, { force: true });
  }
}
async function installSkillUnlocked(
  client: SkillHarborClient,
  slug: string,
  directory: string,
  options: { update?: boolean; expectedVersion?: string },
): Promise<{ targetPath: string; version: string; backupPath?: string }> {
  validateSlug(slug);
  directory = path.resolve(directory);
  await assertNoSymlinkAncestors(directory);
  const targetPath = path.join(directory, slug),
    state = path.join(directory, '.skillharbor');
  await assertNoSymlinkAncestors(path.join(state, 'installs'));
  const existing = await lstat(targetPath).catch(() => null);
  const receipt = (await listInstalled(directory, client.baseUrl)).find(
    (item) => item.slug === slug,
  );
  if (existing && !options.update)
    throw new ClientError('Skill 已存在；使用 update，旧版本会完整备份。', 'already_installed');
  if (existing && (!existing.isDirectory() || existing.isSymbolicLink() || !receipt))
    throw new ClientError('拒绝覆盖非本服务管理的安装。', 'unmanaged_install');
  if (options.update && !existing) throw new ClientError('没有可更新的安装。');
  if (receipt && options.expectedVersion && receipt.version === options.expectedVersion)
    return { targetPath, version: receipt.version };
  const archive = await client.download(slug, options.expectedVersion);
  await assertNoSymlinkAncestors(state);
  await mkdir(path.join(state, 'staging'), { recursive: true, mode: 0o700 });
  const staging = path.join(state, 'staging', slug + '-' + randomUUID());
  await mkdir(staging, { mode: 0o700 });
  let backupPath: string | undefined;
  let moved = false;
  try {
    for (const file of archive.files) {
      const destination = path.join(staging, ...file.path.split('/'));
      await mkdir(path.dirname(destination), { recursive: true });
      const handle = await open(destination, 'wx', 0o644);
      try {
        await handle.writeFile(file.data);
      } finally {
        await handle.close();
      }
    }
    if (existing) {
      await mkdir(path.join(state, 'backups'), { recursive: true, mode: 0o700 });
      backupPath = path.join(
        state,
        'backups',
        slug + '-' + Date.now() + '-' + randomUUID().slice(0, 8),
      );
      await rename(targetPath, backupPath);
      moved = true;
    }
    try {
      await rename(staging, targetPath);
    } catch (error) {
      if (moved && backupPath) await rename(backupPath, targetPath);
      throw error;
    }
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
  await writePrivateJson(path.join(state, 'installs', slug + '.json'), {
    slug,
    version: archive.version,
    origin: client.baseUrl,
    sha256: archive.sha256,
    installedAt: new Date().toISOString(),
    targetPath,
  });
  return { targetPath, version: archive.version, ...(backupPath ? { backupPath } : {}) };
}
export async function checkUpdates(
  client: SkillHarborClient,
  directory: string,
): Promise<
  { slug: string; installedVersion: string; publishedVersion?: string; status: string }[]
> {
  const results = [];
  for (const receipt of await listInstalled(directory, client.baseUrl)) {
    try {
      const { skill } = await client.request<{ skill: SkillSummary }>(
        '/api/skills/' + receipt.slug,
      );
      results.push({
        slug: receipt.slug,
        installedVersion: receipt.version,
        publishedVersion: skill.version,
        status: receipt.version === skill.version ? 'current' : 'update_available',
      });
    } catch (error) {
      if (
        error instanceof ClientError &&
        ['http_403', 'http_404', 'forbidden', 'not_found'].includes(error.code)
      )
        results.push({
          slug: receipt.slug,
          installedVersion: receipt.version,
          status: 'unavailable',
        });
      else throw error;
    }
  }
  return results;
}
