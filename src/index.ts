#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { whoisAsn, whoisDomain, whoisTld, whoisIp } from 'whoiser';
import { green, red, yellow } from './utils.js'

function registerTools(server: McpServer) {
  //TOOL: Domain whois lookup
  server.tool(
    'whois.domain',
    'Looksup whois information about the domain',
    { domain: z.string().min(1) },
    async ({ domain }) => {
      try {
        const result = await whoisDomain(domain);
        return {
          content: [{ type: 'text', text: `Domain whois lookup for: \n${JSON.stringify(result)}` }],
        };
      } catch (err: unknown) {
        const error = err as Error;
        return {
          content: [{ type: 'text', text: `Error: ${error.message}` }],
          isError: true
        };
      }
    }
  );

  //TOOL: TLD whois lookup
  server.tool(
    'whois.tld',
    'Looksup whois information about the Top Level Domain (TLD)',
    { tld: z.string().min(1) },
    async ({ tld }) => {
      try {
        const result = await whoisTld(tld);
        return {
          content: [{ type: 'text', text: `TLD whois lookup for: \n${JSON.stringify(result)}` }],
        };
      } catch (err: unknown) {
        const error = err as Error;
        return {
          content: [{ type: 'text', text: `Error: ${error.message}` }],
          isError: true
        };
      }
    }
  );

  //TOOL: IP whois lookup
  server.tool(
    'whois.ip',
    'Looksup whois information about the IP',
    { ip: z.string().ip() },
    async ({ ip }) => {
      try {
        const result = await whoisIp(ip);
        return {
          content: [{ type: 'text', text: `IP whois lookup for: \n${JSON.stringify(result)}` }],
        };
      } catch (err: unknown) {
        const error = err as Error;
        return {
          content: [{ type: 'text', text: `Error: ${error.message}` }],
          isError: true
        };
      }
    }
  );

  //TOOL: ASN whois lookup
  server.tool(
    'whois.as',
    'Looksup whois information about the Autonomous System Number (ASN)',
    { asn: z.string().regex(/^AS\d+$/i).transform(s => parseInt(s.slice(2))) },
    async ({ asn }) => {
      try {
        const result = await whoisAsn(asn);
        return {
          content: [{ type: 'text', text: `ASN whois lookup for: \n${JSON.stringify(result)}` }],
        };
      } catch (err: unknown) {
        const error = err as Error;
        return {
          content: [{ type: 'text', text: `Error: ${error.message}` }],
          isError: true
        };
      }
    }
  );
}

async function main() {
  const server = new McpServer({
    name: 'whois',
    version: '1.0.0',
    description: 'MCP for whois lookup about domain, IP, TLD, ASN, etc.',
  });
  registerTools(server);

	let transport = new StdioServerTransport();
	await server.connect(transport);

	const cleanup = async () => {
		console.log(yellow('\n⚠️ Shutting down MCP server...'));
    await transport.close();
    process.exit(0);
	};

	process.on('SIGINT', cleanup);
	process.on('SIGTERM', cleanup);

	console.error(green('✅ Whois MCP Server running on stdio'));
}

function handleError(error: any) {
	console.error(red('\n🚨  Error initializing Whois MCP server:\n'));
	console.error(yellow(`   ${error.message}\n`));
}

main().catch((error) => {
	handleError(error);
});
