import React, { createContext, useContext, useEffect, useState, useRef } from 'react';

interface WebSocketContextType {
  lastEvent: any | null;
  subscribeEmail: (emailId: string) => void;
  unsubscribeEmail: (emailId: string) => void;
}

const WebSocketContext = createContext<WebSocketContextType | undefined>(undefined);

export const WebSocketProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [lastEvent, setLastEvent] = useState<any | null>(null);
  const activeSockets = useRef<Map<string, WebSocket>>(new Map());

  const subscribeEmail = (emailId: string) => {
    if (activeSockets.current.has(emailId)) return;

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/ws/email/${emailId}`;

    const ws = new WebSocket(wsUrl);

    ws.onmessage = (event) => {
      try {
        const parsed = JSON.parse(event.data);
        setLastEvent(parsed);
      } catch (e) {
        console.error('Failed to parse WS event', e);
      }
    };

    ws.onclose = () => {
      activeSockets.current.delete(emailId);
    };

    activeSockets.current.set(emailId, ws);
  };

  const unsubscribeEmail = (emailId: string) => {
    const ws = activeSockets.current.get(emailId);
    if (ws) {
      ws.close();
      activeSockets.current.delete(emailId);
    }
  };

  useEffect(() => {
    return () => {
      activeSockets.current.forEach((ws) => ws.close());
      activeSockets.current.clear();
    };
  }, []);

  return (
    <WebSocketContext.Provider value={{ lastEvent, subscribeEmail, unsubscribeEmail }}>
      {children}
    </WebSocketContext.Provider>
  );
};

export const useWebSocket = () => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error('useWebSocket must be used within a WebSocketProvider');
  }
  return context;
};
