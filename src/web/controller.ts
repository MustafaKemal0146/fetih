/**
 * @fileoverview Web UI controller — no-op stub.
 * Web sürümü v4.x'te kaldırıldı. Bu modül çağrı sitelerini değiştirmemek için
 * boş metodlarla tutuldu; hiçbir mesaj WebSocket'e gönderilmez, hiçbir callback tetiklenmez.
 */

import type { ChatMessage } from '../types.js';

export interface WebUIEvent {
  type: string;
  data: unknown;
}

class WebUIController {
  setServer(_wss: unknown): void {}
  onUserInput(_cb: (text: string) => void): void {}
  handleWebInput(_text: string): void {}
  onWebCommand(_cb: (text: string) => void): void {}
  handleWebCommand(_text: string): void {}
  sendCommandResult(_output: string): void {}
  onWebAbort(_cb: () => void): void {}
  handleWebAbort(): void {}
  onGetModels(_cb: (provider: string) => void): void {}
  handleGetModels(_provider: string): void {}
  getApiKeyStatus(): { keys: Record<string, { hasKey: boolean }> } { return { keys: {} }; }
  setApiKey(_provider: string, _apiKey: string): { success: boolean; error?: string } {
    return { success: false, error: 'Web UI v4.x ile kaldırıldı' };
  }
  sendModels(_provider: string, _models: string[]): void {}
  broadcast(_event: WebUIEvent): void {}
  sendText(_chunk: string): void {}
  sendToolCall(_name: string, _input: Record<string, unknown>): void {}
  sendToolResult(_name: string, _output: string, _isError: boolean): void {}
  sendHistory(_messages: ChatMessage[]): void {}
  sendStatus(_status: string, _processing: boolean): void {}
  sendStats(_stats: unknown): void {}
  sendEffort(_level: string): void {}
  sendSettings(_settings: unknown): void {}
  sendDiff(_filename: string, _diff: string): void {}
  sendPlanProposal(_planText: string): void {}
  sendTasks(_tasks: unknown[]): void {}
  sendWarning(_message: string, _toolName?: string): void {}
}

export const webUIController = new WebUIController();
