import React, { useState, useEffect } from "react";
import AuthSetup from "./components/AuthSetup";
import ModelSelector from "./components/ModelSelector";
import ChatInterface from "./components/ChatInterface";
import logo from "./Prjna-logo.jpg";


function App() {
  const [authStatus, setAuthStatus] = useState(null);
  const [currentView, setCurrentView] = useState('landing');
  const [selectedModel, setSelectedModel] = useState('');
  const [selectedProvider, setSelectedProvider] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [chatHistory, setChatHistory] = useState([]);
  const [activeChat, setActiveChat] = useState(0);
  const [showTgptComingSoon, setShowTgptComingSoon] = useState(false);
  const [pendingProvider, setPendingProvider] = useState(null);


  // Persistent chat history and selected model
  useEffect(() => {
    // Load from localStorage on mount
    const savedHistory = localStorage.getItem('prajna_chat_history');
    const savedModel = localStorage.getItem('prajna_selected_model');
    const savedProvider = localStorage.getItem('prajna_selected_provider');
    const savedActive = localStorage.getItem('prajna_active_chat');
    if (savedHistory) setChatHistory(JSON.parse(savedHistory));
    if (savedModel) setSelectedModel(savedModel);
    if (savedProvider) setSelectedProvider(savedProvider);
    if (savedActive) setActiveChat(Number(savedActive));
  }, []);

  useEffect(() => {
    // Save to localStorage on change
    localStorage.setItem('prajna_chat_history', JSON.stringify(chatHistory));
    localStorage.setItem('prajna_selected_model', selectedModel);
    localStorage.setItem('prajna_selected_provider', selectedProvider);
    localStorage.setItem('prajna_active_chat', String(activeChat));
    // Persist to backend
    fetch('http://localhost:5000/api/history', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chats: chatHistory })
    }).catch(() => {});
  }, [chatHistory, selectedModel, selectedProvider, activeChat]);

  useEffect(() => {
    if (currentView !== 'landing') {
      checkAuthStatus();
    }
  }, [currentView]);

  const checkAuthStatus = async () => {
    try {
      const response = await fetch("http://localhost:5000/api/auth/status");
      const data = await response.json();
      setAuthStatus(data);
      // Only update view if not already in chat
      setCurrentView(prev => {
        if (prev === 'chat') return 'chat';
        return data.configured ? 'model-select' : 'auth';
      });
      // Sync history from backend (optional)
      fetch('http://localhost:5000/api/history')
        .then(r => r.json())
        .then(h => { if (Array.isArray(h.chats)) setChatHistory(h.chats); })
        .catch(() => {});
    } catch (error) {
      console.error("Failed to check auth status:", error);
      setCurrentView('auth');
    } finally {
      setIsLoading(false);
    }
  };

  const handleAuthSuccess = (provider) => {
    setSelectedProvider(provider);
    setSelectedModel('');
    setPendingProvider(null);
    setCurrentView('chat');
  };

  const handleModelSelect = (model) => {
    setSelectedModel(model);
    setCurrentView('chat');
  };

  const handleResetAuth = async (provider = null) => {
    try {
      await fetch("http://localhost:5000/api/auth/reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider })
      });
      localStorage.removeItem('prajna_chat_history');
      localStorage.removeItem('prajna_selected_model');
      localStorage.removeItem('prajna_selected_provider');
      await checkAuthStatus();
      setCurrentView('auth');
    } catch (error) {
      console.error("Failed to reset auth:", error);
    }
  };

  const handleNewChat = () => {
    const createdAt = Date.now();
    setChatHistory([...chatHistory, [{ role: 'system', content: 'New session started', ts: createdAt }]]);
    setActiveChat(chatHistory.length);
  };

  const handleSelectChat = (idx) => {
    setActiveChat(idx);
  };

  const handleUpdateChat = (messages) => {
    const updated = [...chatHistory];
    updated[activeChat] = messages;
    setChatHistory(updated);
  };


  if (isLoading && currentView !== 'landing') {
    return (
      <div className="flex items-center justify-center h-screen bg-black text-green-400">
        <div className="text-center">
          <div className="animate-spin rounded-full h-20 w-20 border-b-2 border-green-400 mx-auto mb-4"></div>
          <p>Loading Prajna...</p>
        </div>
      </div>
    );
  }

  if (currentView === 'landing') {
    return (
      <div className="h-screen bg-black text-green-400 font-mono flex items-center justify-center">
        <div className="text-center">
          <img src={logo} alt="Prajna Logo" className="h-24 w-24 rounded-full mx-auto mb-6" />
          <h1 className="text-4xl font-bold mb-4">Welcome to prajna</h1>
          <h2 className="text-2xl mb-8">The next-gen AI assistant for SIEM on the Solunk, specially</h2>
          <button className="px-8 py-3 bg-green-700 rounded text-white text-xl" onClick={() => setCurrentView('auth')}>Get Started</button>
        </div>
      </div>
    );
  }

  if (showTgptComingSoon) {
    return (
      <div className="h-screen bg-black text-green-400 font-mono flex items-center justify-center">
        <div className="text-center bg-gray-900 p-12 rounded-xl shadow-lg border-2 border-green-700">
          <img src={logo} alt="Prajna Logo" className="h-24 w-24 rounded-full mx-auto mb-6" />
          <h1 className="text-4xl font-bold mb-4">tgpt Version Coming Soon!</h1>
          <h2 className="text-xl mb-8">Kindly wait and use other models below:</h2>
          <div className="flex gap-6 justify-center mb-8">
            <button className="px-8 py-3 bg-blue-700 rounded text-white text-xl" onClick={() => { setPendingProvider('openai'); setShowTgptComingSoon(false); setCurrentView('auth'); }}>OpenAI</button>
            <button className="px-8 py-3 bg-purple-700 rounded text-white text-xl" onClick={() => { setPendingProvider('gemini'); setShowTgptComingSoon(false); setCurrentView('auth'); }}>Gemini</button>
            <button className="px-8 py-3 bg-yellow-700 rounded text-white text-xl" onClick={() => { setPendingProvider('claude'); setShowTgptComingSoon(false); setCurrentView('auth'); }}>Claude</button>
          </div>
          <button className="mt-4 px-6 py-2 bg-gray-700 rounded text-white" onClick={() => { setShowTgptComingSoon(false); setCurrentView('auth'); }}>Back</button>
        </div>
      </div>
    );
  }

  return (
    <div className="h-screen bg-gradient-to-b from-black via-gray-950 to-black text-emerald-300 flex">
      {/* Sidebar */}
      <div className="w-80 bg-gray-900/80 backdrop-blur h-full flex flex-col p-6 border-r border-emerald-800/30 text-emerald-300" style={{color: '#6ee7b7'}}>
        <div className="flex items-center mb-8">
          <img src={logo} alt="Prajna Logo" className="h-12 w-12 rounded-full mr-3 shadow-lg" />
          <span className="text-2xl font-bold tracking-tight drop-shadow-[0_0_8px_rgba(16,185,129,0.30)] text-emerald-300">Prajna</span>
        </div>
        <button className="mb-6 px-6 py-3 bg-emerald-700 hover:bg-emerald-600 transition rounded-lg text-white font-semibold shadow-lg" onClick={handleNewChat}>New Chat</button>
        <div className="flex-1 overflow-y-auto">
          <h3 className="text-lg mb-4 font-semibold text-emerald-200">History</h3>
          {chatHistory.length === 0 && <div className="text-gray-400 text-sm">No chats yet.</div>}
          {chatHistory.map((c, idx) => {
            const firstUserMsg = (c || []).find(m => m && m.role === 'user');
            const title = firstUserMsg?.content?.slice(0, 40) || `Chat ${idx + 1}`;
            const lastTs = (c || []).reduce((acc, m) => Math.max(acc, m?.ts || 0), 0);
            const lastStr = lastTs ? new Date(lastTs).toLocaleString() : '';
            const hasFile = (c || []).some(m => m?.role === 'file');
            return (
              <div key={idx} className={`mb-3 p-4 rounded-xl cursor-pointer border transition hover:scale-[1.02] ${activeChat === idx ? 'bg-emerald-800/60 text-emerald-100 border-emerald-500/60 shadow-lg' : 'bg-gray-800/50 text-emerald-300 border-gray-700/50 hover:bg-gray-800/70'}`} onClick={() => handleSelectChat(idx)} style={{color: activeChat === idx ? '#d1fae5' : '#6ee7b7'}}>
                <div className="flex items-center justify-between gap-2">
                  <div className="truncate max-w-[200px] font-semibold text-sm" style={{color: 'inherit'}}>{title}</div>
                  {hasFile && <span className="px-2 py-0.5 rounded-full text-xs bg-amber-900/40 border border-amber-600/50 text-amber-200">files</span>}
                </div>
                <div className="text-xs text-emerald-300/60 mt-2" style={{color: '#6ee7b7'}}>{lastStr}</div>
              </div>
            );
          })}
        </div>
      </div>
      {/* Main Content */}
      <div className="flex-1 h-full">
        {currentView === 'auth' && (
          <AuthSetup 
            authStatus={authStatus} 
            onSuccess={handleAuthSuccess}
            onReset={handleResetAuth}
            pendingProvider={pendingProvider}
          />
        )}
        {currentView === 'model-select' && (
          <ModelSelector 
            authStatus={authStatus}
            onModelSelect={handleModelSelect}
            onBack={() => setCurrentView('auth')}
          />
        )}
        {currentView === 'chat' && (
          <ChatInterface 
            authStatus={authStatus}
            selectedModel={selectedModel}
            selectedProvider={selectedProvider}
            onSettingsClick={() => setCurrentView('model-select')}
            onResetAuth={handleResetAuth}
            chat={chatHistory[activeChat] || []}
            onUpdateChat={handleUpdateChat}
          />
        )}
      </div>
    </div>
  );
}

export default App;