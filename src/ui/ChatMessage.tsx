import React from 'react';
import { Box, Text } from 'ink';
import type { ChatMessage as MessageType, ContentBlock } from '../types.js';

export interface ChatMessageProps {
  message: MessageType;
  isStreaming?: boolean;
}

function renderContent(content: string | ContentBlock[]) {
  if (typeof content === 'string') {
    return content;
  }
  return content
    .filter(b => b.type === 'text' || b.type === 'tool_result')
    .map(b => {
      if (b.type === 'text') return b.text;
      if (b.type === 'tool_result') return `\n[ARAÇ ÇIKTISI]:\n${b.content}\n`;
      return '';
    })
    .join('');
}

export function ChatMessage({ message, isStreaming }: ChatMessageProps) {
  const isUser = message.role === 'user';
  const roleLabel = isUser ? ' KULLANICI ' : ' SETH ';
  
  // Tema: Crimson Hacker
  const roleColor = 'red';
  const borderColor = isUser ? 'gray' : 'red';
  const labelBg = isUser ? 'white' : 'red';
  const labelText = isUser ? 'black' : 'white';

  const text = renderContent(message.content);
  if (!text && !isStreaming) return null;

  if (message.role === 'system') return null;

  return (
    <Box flexDirection="column" marginBottom={1} width="100%">
      <Box paddingLeft={1}>
        <Text bold color={labelText} backgroundColor={labelBg}>
          {roleLabel}
        </Text>
      </Box>
      <Box 
        borderStyle="round" 
        borderColor={borderColor} 
        paddingX={1} 
        flexDirection="column"
      >
        <Text color={isUser ? 'white' : 'red'}>{text}</Text>
        {isStreaming && <Text color="red">▋</Text>}
      </Box>
    </Box>
  );
}
