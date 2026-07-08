import express from "express";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import {
  scanRepository,
  scanLiveCluster,
  renderMarkdown,
} from "./scanner/scan_eks_maturity.mjs";

// ---------------------------------------------------------------------------
// MCP server factory — one fresh McpServer per HTTP session, tools call
// straight into the existing eks-maturity-advisor scanner functions.
// ---------------------------------------------------------------------------
function buildServer() {
  const server = new McpServer({
    name: "eks-maturity-advisor",
    version: "1.0.0",
  });

  server.registerTool(
    "scan_repo",
    {
      title: "Scan repo for EKS maturity",
      description:
        "Read-only static scan of a repository (Terraform / Kubernetes manifests) against the EKS Maturity Model Quick Wins and Foundational controls.",
      inputSchema: {
        repoRoot: z
          .string()
          .describe("Absolute path to the repository root to scan"),
      },
    },
    async ({ repoRoot }) => {
      const report = scanRepository({ repoRoot });
      return { content: [{ type: "text", text: renderMarkdown(report) }] };
    }
  );

  server.registerTool(
    "scan_live_cluster",
    {
      title: "Scan live EKS cluster (read-only)",
      description:
        "Read-only scan of a live EKS cluster via kubectl/aws CLI against the maturity model's Foundational live-checkable controls. Never mutates the cluster or AWS account.",
      inputSchema: {
        clusterName: z.string().describe("EKS cluster name"),
        region: z.string().describe("AWS region, e.g. ap-northeast-2"),
        context: z
          .string()
          .optional()
          .describe("kubectl context to use (optional)"),
        profile: z
          .string()
          .optional()
          .describe("AWS CLI profile to use (optional)"),
      },
    },
    async ({ clusterName, region, context, profile }) => {
      const report = scanLiveCluster({ clusterName, region, context, profile });
      return { content: [{ type: "text", text: renderMarkdown(report) }] };
    }
  );

  return server;
}

// ---------------------------------------------------------------------------
// stdio mode — for local testing with `node server.mjs --stdio`
// (e.g. Claude Desktop local config) before deploying the HTTP version.
// ---------------------------------------------------------------------------
async function runStdio() {
  const server = buildServer();
  await server.connect(new StdioServerTransport());
}

// ---------------------------------------------------------------------------
// HTTP mode — Streamable HTTP transport, one transport per mcp-session-id,
// meant to be deployed somewhere reachable and shared by the whole team.
// ---------------------------------------------------------------------------
function runHttp() {
  const app = express();
  app.use(express.json());

  const apiKey = process.env.MCP_API_KEY;
  if (!apiKey) {
    console.warn(
      "WARNING: MCP_API_KEY is not set — /mcp is reachable by anyone with the URL."
    );
  }

  app.use((req, res, next) => {
    if (!apiKey) return next();
    if (req.headers["x-api-key"] === apiKey) return next();
    res.status(401).json({ error: "unauthorized" });
  });

  /** @type {Record<string, StreamableHTTPServerTransport>} */
  const transports = {};

  app.post("/mcp", async (req, res) => {
    const sessionId = req.headers["mcp-session-id"];
    let transport = sessionId ? transports[sessionId] : undefined;

    if (!transport && isInitializeRequest(req.body)) {
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
        onsessioninitialized: (id) => {
          transports[id] = transport;
        },
      });
      transport.onclose = () => {
        if (transport.sessionId) delete transports[transport.sessionId];
      };
      await buildServer().connect(transport);
    } else if (!transport) {
      res.status(400).json({
        jsonrpc: "2.0",
        error: { code: -32000, message: "Bad Request: no valid session" },
        id: null,
      });
      return;
    }

    await transport.handleRequest(req, res, req.body);
  });

  const handleSessionRequest = async (req, res) => {
    const sessionId = req.headers["mcp-session-id"];
    const transport = sessionId ? transports[sessionId] : undefined;
    if (!transport) {
      res.status(400).send("Invalid or missing session ID");
      return;
    }
    await transport.handleRequest(req, res);
  };

  app.get("/mcp", handleSessionRequest);
  app.delete("/mcp", handleSessionRequest);

  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`eks-maturity-advisor MCP server listening on :${port}/mcp`);
  });
}

if (process.argv.includes("--stdio")) {
  await runStdio();
} else {
  runHttp();
}
