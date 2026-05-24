/**
 * FETIH MCP Bridge — FETIH CTF/OSINT/Git araçlarını FETIH'e MCP üzerinden açar.
 *
 * Başlatmak: node dist/bridge/mcp-server.js
 * FETIH config: mcp_servers.fetih-tools.command = node
 *                mcp_servers.fetih-tools.args = [".../dist/bridge/mcp-server.js"]
 */
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { ListToolsRequestSchema, CallToolRequestSchema, } from '@modelcontextprotocol/sdk/types.js';
// ─── CTF Araçları ─────────────────────────────────────────────────────────────
import { ctfHashTool } from '../tools/ctf/ctf-hash.js';
import { ctfRsaTool } from '../tools/ctf/ctf-rsa.js';
import { ctfAesHelperTool } from '../tools/ctf/ctf-aes-helper.js';
import { ctfAudioAnalyzerTool } from '../tools/ctf/ctf-audio-analyzer.js';
import { ctfAutoTool } from '../tools/ctf/ctf-auto.js';
import { ctfBinaryAnalyzerTool } from '../tools/ctf/ctf-binary-analyzer.js';
import { ctfClassifyTool } from '../tools/ctf/ctf-classify.js';
import { ctfFileAnalyzerTool } from '../tools/ctf/ctf-file-analyzer.js';
import { ctfForensicsTool } from '../tools/ctf/ctf-forensics.js';
import { ctfJwtTool } from '../tools/ctf/ctf-jwt.js';
import { ctfMobileTool } from '../tools/ctf/ctf-mobile.js';
import { ctfNetworkAnalyzerTool } from '../tools/ctf/ctf-network-analyzer.js';
import { ctfOcrTool } from '../tools/ctf/ctf-ocr.js';
import { ctfPwnTool } from '../tools/ctf/ctf-pwn.js';
import { ctfSolverTool } from '../tools/ctf/ctf-solver.js';
import { ctfStegoTool } from '../tools/ctf/ctf-stego.js';
import { ctfWebAnalyzerTool } from '../tools/ctf/ctf-web-analyzer.js';
import { interactiveSessionTool } from '../tools/ctf/interactive-session.js';
import { pwnSessionTool } from '../tools/ctf/pwn-session.js';
// ─── OSINT Araçları ──────────────────────────────────────────────────────────
import { shodanTool } from '../tools/osint/shodan.js';
// ─── Git Araçları ────────────────────────────────────────────────────────────
import { gitStatusTool } from '../tools/git/git-status.js';
import { gitDiffTool } from '../tools/git/git-diff.js';
import { gitLogTool } from '../tools/git/git-log.js';
import { gitWorktreeTool } from '../tools/git/git-worktree.js';
// ─── Araç Listesi ─────────────────────────────────────────────────────────────
const allTools = [
    // CTF
    ctfHashTool,
    ctfRsaTool,
    ctfAesHelperTool,
    ctfAudioAnalyzerTool,
    ctfAutoTool,
    ctfBinaryAnalyzerTool,
    ctfClassifyTool,
    ctfFileAnalyzerTool,
    ctfForensicsTool,
    ctfJwtTool,
    ctfMobileTool,
    ctfNetworkAnalyzerTool,
    ctfOcrTool,
    ctfPwnTool,
    ctfSolverTool,
    ctfStegoTool,
    ctfWebAnalyzerTool,
    interactiveSessionTool,
    pwnSessionTool,
    // OSINT
    shodanTool,
    // Git
    gitStatusTool,
    gitDiffTool,
    gitLogTool,
    gitWorktreeTool,
];
// ─── MCP Sunucusu ─────────────────────────────────────────────────────────────
const server = new Server({ name: 'fetih-tools', version: '1.0.0' }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: allTools.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
    })),
}));
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const toolName = request.params.name;
    const tool = allTools.find((t) => t.name === toolName);
    if (!tool) {
        return {
            content: [{ type: 'text', text: `Araç bulunamadı: ${toolName}` }],
            isError: true,
        };
    }
    try {
        const result = await tool.execute((request.params.arguments ?? {}), process.cwd());
        return {
            content: [{ type: 'text', text: result.output }],
            isError: result.isError ?? false,
        };
    }
    catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return {
            content: [{ type: 'text', text: `Araç hatası [${toolName}]: ${msg}` }],
            isError: true,
        };
    }
});
const transport = new StdioServerTransport();
await server.connect(transport);
