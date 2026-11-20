/**
 * Minimal desktop bridge following Lumo Desktop's namespaced-tool convention.
 * This is original code; no Proton auth, Mail, or hosted account coupling.
 */
import { invoke } from '@tauri-apps/api/core';

export interface ToolSpec {
  type: 'function';
  function: { name: string; description: string; parameters: Record<string, unknown> };
}
export interface ToolCall { name: string; arguments: Record<string, unknown> }
export interface ApprovalEvent { id: string; tool: string; preview: string }

export interface AgentSettings {
  allowed_roots: string[];
  policies: Record<string, 'auto' | 'ask' | 'disable'>;
}
export interface ConnectorBridge {
  settings(): Promise<AgentSettings>;
  list(): Promise<ToolSpec[]>;
  invoke(call: ToolCall): Promise<unknown>;
  setPolicy(tool: string, policy: 'auto' | 'ask' | 'disable'): Promise<void>;
  setAllowedRoots(roots: string[]): Promise<void>;
  respondApproval(id: string, allow: boolean): Promise<boolean>;
  status(): Promise<{ binding: string; vpn_active: boolean; online: boolean; error: string | null }>;
  previewWireGuardPeer(publicKey: string, tunnelIp: string): Promise<string>;
}

export const connectorBridge: ConnectorBridge = {
  list: () => invoke('list_tools'),
  settings: () => invoke('get_agent_settings'),
  invoke: (call) => invoke('invoke_tool', { call }),
  setPolicy: (tool, policy) => invoke('set_tool_policy', { tool, policy }),
  setAllowedRoots: (roots) => invoke('set_allowed_roots', { roots }),
  respondApproval: (id, allow) => invoke('respond_approval', { id, allow }),
  status: () => invoke('get_agent_status'),
  previewWireGuardPeer: (publicKey, tunnelIp) => invoke('preview_wireguard_peer', { publicKey, tunnelIp }),
};

declare global {
  interface Window { LumoConnectors: ConnectorBridge }
}
window.LumoConnectors = connectorBridge;
