#!/usr/bin/env node
import path from 'node:path';
import { lstat, mkdir, open } from 'node:fs/promises';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import {
  ClientError,
  DeviceFlow,
  SkillHarborClient,
  checkUpdates,
  installSkill,
  isMainModule,
  listInstalled,
  openBrowser,
  skillsDirectory,
} from './core.js';
import { product } from './product.js';

export function createMcpServer(client = new SkillHarborClient()): McpServer {
  const server = new McpServer(
    { name: product.mcp, version: product.version },
    {
      instructions:
        'Search this registry for skills the user can access. Inspect metadata and permissions before downloading. All downloads and updates share server-side user quotas regardless of client. Install only a user-selected skill and version; never execute downloaded scripts during installation. connect_account starts browser approval; poll connection_status after pollAfterSeconds. Never request or print access tokens. The local CLI and MCP share the credential for this service origin. Keyword/intent search is explicitly labeled; only provider-backed semantic mode is semantic search.',
    },
  );
  let pending: DeviceFlow | undefined;
  let authQueue: Promise<unknown> = Promise.resolve();
  const serialAuth = <T>(operation: () => Promise<T>): Promise<T> => {
    const next = authQueue.then(operation);
    authQueue = next.catch(() => {});
    return next;
  };
  const result = (data: unknown) => ({
    content: [{ type: 'text' as const, text: JSON.stringify(data) }],
  });
  const safe = async (fn: () => Promise<unknown>) => {
    try {
      return result(await fn());
    } catch (error) {
      return {
        ...result(
          error instanceof ClientError
            ? {
                error: {
                  code: error.code,
                  message: error.message,
                  ...(error.retryAfter ? { retryAfter: error.retryAfter } : {}),
                },
              }
            : { error: { code: 'request_failed', message: '请求失败，请检查服务配置和网络。' } },
        ),
        isError: true,
      };
    }
  };
  const readOnly = { readOnlyHint: true, destructiveHint: false, openWorldHint: true };
  const targetShape = {
    agent: z.enum(['shared', 'claude-code', 'codex', 'cursor']).default('shared'),
    targetDirectory: z.string().max(4096).optional(),
  };
  function target(args: { agent?: string; targetDirectory?: string }): string {
    if (args.targetDirectory && !path.isAbsolute(args.targetDirectory))
      throw new ClientError('安装父目录必须为绝对路径。');
    return skillsDirectory(args.agent, args.targetDirectory);
  }
  server.registerTool(
    'search_skills',
    {
      title: '搜索技能',
      description:
        'Search visible skills by desired output in natural language. Results carry the actual retrieval mode (keyword/intent or provider-backed semantic); do not claim semantic retrieval when it falls back.',
      inputSchema: {
        query: z.string().max(500).default(''),
        category: z.string().max(100).optional(),
      },
      annotations: readOnly,
    },
    (args) =>
      safe(() =>
        client.request(
          '/api/skills?' +
            new URLSearchParams({
              q: args.query,
              ...(args.category ? { category: args.category } : {}),
            }),
        ),
      ),
  );
  server.registerTool(
    'get_skill',
    {
      title: '查看技能',
      description:
        'Read one authorized skill, latest metadata and published versions. Package contents are visible only with the required server-side grants.',
      inputSchema: { slug: z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/) },
      annotations: readOnly,
    },
    (args) => safe(() => client.request('/api/skills/' + args.slug)),
  );
  server.registerTool(
    'get_skill_access',
    {
      title: '检查技能权限',
      description:
        'Check package download permission and current shared user quota without downloading or consuming quota. Download checks again.',
      inputSchema: { slug: z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/) },
      annotations: readOnly,
    },
    (args) => safe(() => client.request(`/api/skills/${args.slug}/access`)),
  );
  server.registerTool(
    'account_status',
    {
      title: '账户状态',
      description:
        'Return the current account, effective quota, usage and search mode. Does not return credentials.',
      inputSchema: {},
      annotations: readOnly,
    },
    () => safe(() => client.request('/api/me')),
  );
  server.registerTool(
    'connect_account',
    {
      title: '连接账户',
      description:
        'Start browser device authorization when the user requests connection. Show the matching user code and URL, then poll connection_status after the returned interval. Never ask for an API key.',
      inputSchema: {},
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    },
    () =>
      safe(() =>
        serialAuth(async () => {
          if (!pending || Date.now() >= pending.startedAt + pending.expiresIn * 1000)
            pending = await client.startDevice();
          const browserOpened = await openBrowser(pending.verificationUri);
          return {
            status: 'pending',
            userCode: pending.userCode,
            verificationUri: pending.verificationUri,
            expiresAt: new Date(pending.startedAt + pending.expiresIn * 1000).toISOString(),
            pollAfterSeconds: Math.max(1, Math.ceil((pending.nextPollAt - Date.now()) / 1000)),
            browserOpened,
          };
        }),
      ),
  );
  server.registerTool(
    'connection_status',
    {
      title: '检查连接进度',
      description:
        'Poll a pending device authorization after pollAfterSeconds. Stores the authorized credential locally and never returns it.',
      inputSchema: {},
      annotations: { ...readOnly, readOnlyHint: false },
    },
    () =>
      safe(() =>
        serialAuth(async () => {
          if (!pending) return { status: 'not_started' };
          try {
            const status = await client.pollDevice(pending);
            if (status.status === 'connected') pending = undefined;
            return status;
          } catch (error) {
            if (
              error instanceof ClientError &&
              ['expired_token', 'access_denied'].includes(error.code)
            )
              pending = undefined;
            throw error;
          }
        }),
      ),
  );
  server.registerTool(
    'disconnect_account',
    {
      title: '断开账户',
      description:
        'When the user requests, revoke the shared CLI/MCP session and remove its local credential. A server outage may prevent remote revocation.',
      inputSchema: {},
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
    },
    () =>
      safe(() =>
        serialAuth(async () => {
          pending = undefined;
          return client.logout();
        }),
      ),
  );
  server.registerTool(
    'list_installed_skills',
    {
      title: '列出本地安装',
      description:
        'List local installations recorded by this SkillHarbor origin. Does not read credentials or execute skills.',
      inputSchema: targetShape,
      annotations: { ...readOnly, openWorldHint: false },
    },
    (args) => safe(async () => ({ skills: await listInstalled(target(args), client.baseUrl) })),
  );
  server.registerTool(
    'check_updates',
    {
      title: '检查更新',
      description:
        'Compare managed local versions with the visible published release. Does not download or consume pull quota. Ask the user to select a version before update_skill.',
      inputSchema: targetShape,
      annotations: readOnly,
    },
    (args) => safe(async () => ({ skills: await checkUpdates(client, target(args)) })),
  );
  server.registerTool(
    'install_skill',
    {
      title: '安装技能',
      description:
        'Install a user-selected Skill into an explicit agent folder. Rechecks permission and shared quota, verifies the package, and refuses existing directories. Never executes a Skill.',
      inputSchema: {
        ...targetShape,
        slug: z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/),
        expectedVersion: z.string().min(1).max(64).optional(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    },
    (args) =>
      safe(() =>
        installSkill(client, args.slug, target(args), { expectedVersion: args.expectedVersion }),
      ),
  );
  server.registerTool(
    'update_skill',
    {
      title: '更新技能',
      description:
        'Only after the user selects an exact published version, update a Skill managed by this origin. Backs up the entire previous directory including local edits. Cannot replace foreign/unmanaged installs.',
      inputSchema: {
        ...targetShape,
        slug: z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/),
        expectedVersion: z.string().min(1).max(64),
      },
      annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
    },
    (args) =>
      safe(() =>
        installSkill(client, args.slug, target(args), {
          update: true,
          expectedVersion: args.expectedVersion,
        }),
      ),
  );
  server.registerTool(
    'download_skill',
    {
      title: '下载技能包',
      description:
        'Save a verified Skill ZIP to a user-selected absolute directory. Consumes the same server pull quota as every other channel. Never installs or executes files and never overwrites an archive.',
      inputSchema: {
        slug: z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/),
        downloadDirectory: z.string().min(1).max(4096),
        expectedVersion: z.string().min(1).max(64).optional(),
      },
      annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
    },
    (args) =>
      safe(async () => {
        if (!path.isAbsolute(args.downloadDirectory))
          throw new ClientError('下载目录必须为绝对路径。');
        const directory = path.resolve(args.downloadDirectory);
        const info = await lstat(directory).catch(() => null);
        if (info && (!info.isDirectory() || info.isSymbolicLink()))
          throw new ClientError('下载目录必须是普通目录。');
        const archive = await client.download(args.slug, args.expectedVersion);
        await mkdir(directory, { recursive: true });
        const archivePath = path.join(directory, `${args.slug}-${archive.sha256.slice(0, 12)}.zip`);
        const file = await open(archivePath, 'wx', 0o600);
        try {
          await file.writeFile(archive.bytes);
        } finally {
          await file.close();
        }
        return { archivePath, slug: args.slug, version: archive.version, sha256: archive.sha256 };
      }),
  );
  return server;
}

export async function main(args = process.argv.slice(2)): Promise<void> {
  if (args.length && !(args.length === 2 && args[0] === '--url'))
    throw new ClientError(`用法: ${product.mcp} [--url <origin>]`);
  const server = createMcpServer(new SkillHarborClient(args[1]));
  await server.connect(new StdioServerTransport());
}
if (isMainModule(import.meta.url))
  main().catch(() => {
    console.error('SkillHarbor MCP 启动失败，请检查服务地址与客户端配置。');
    process.exitCode = 1;
  });
