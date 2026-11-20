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

export interface ConnectorBridge {
  list(): Promise<ToolSpec[]>;
  invoke(call: ToolCall): Promise<unknown>;
  setPolicy(tool: string, policy: 'auto' | 'ask' | 'disable'): Promise<void>;
  setAllowedRoots(roots: string[]): Promise<void>;
  respondApproval(id: string, allow: boolean): Promise<boolean>;
  status(): Promise<{ binding: string; vpn_active: boolean }>;
}

export const connectorBridge: ConnectorBridge = {
  list: () => invoke('list_tools'),
  invoke: (call) => invoke('invoke_tool', { call }),
  setPolicy: (tool, policy) => invoke('set_tool_policy', { tool, policy }),
  setAllowedRoots: (roots) => invoke('set_allowed_roots', { roots }),
  respondApproval: (id, allow) => invoke('respond_approval', { id, allow }),
  status: () => invoke('get_agent_status'),
};

declare global {
  interface Window { LumoConnectors: ConnectorBridge }
}
window.LumoConnectors = connectorBridge;
