import React, { useState, useEffect, useRef } from "react";

const ChatInterface = ({ authStatus, selectedModel, selectedProvider, onSettingsClick, onResetAuth, chat, onUpdateChat }) => {
	const tgptFeatures = [
		{ value: '', label: 'Chat (default)' },
		{ value: 'code', label: 'Code Generation' },
		{ value: 'shell', label: 'Shell Command' },
		{ value: 'img', label: 'Image Generation' },
		{ value: 'whole', label: 'Whole Text' }
	];
	const [tgptFlag, setTgptFlag] = useState('');
	const [tgptOptions, setTgptOptions] = useState({});
	const [splunkStatus, setSplunkStatus] = useState(null);
	const [message, setMessage] = useState("");
	const [loading, setLoading] = useState(false);
	const [error, setError] = useState("");
	const [showFilePicker, setShowFilePicker] = useState(false);
	const [file, setFile] = useState(null);
	const [fileResult, setFileResult] = useState("");
	const chatEndRef = useRef(null);
	const fileInputRef = useRef();

	useEffect(() => {
		fetch("http://localhost:5000/test")
			.then(res => res.json())
			.then(data => setSplunkStatus(data.splunkConnected ? "Connected" : "Not Connected"))
			.catch(() => setSplunkStatus("Error"));
	}, []);

	useEffect(() => {
		chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
	}, [chat]);

	// Show Splunk and tgpt errors in UI
	useEffect(() => {
		if (splunkStatus === "Error") {
			setError("Splunk connection failed. Check your .env and Splunk server status.");
		}
	}, [splunkStatus]);

	const sendMessage = async () => {
		if (!message.trim()) return;
		setLoading(true);
		setError("");
		const now = Date.now();
		const newChat = [...chat, { role: "user", content: message, ts: now }];
		onUpdateChat(newChat);
		try {
			const res = await fetch("http://localhost:5000/query", {
				method: "POST",
				headers: { "Content-Type": "application/json" },
				body: JSON.stringify({ message, provider: selectedProvider === 'tgpt' ? 'tgpt' : 'openai', tgptFlag, tgptOptions })
			});
			const data = await res.json();
			if (!res.ok || data.error || data.stderr) {
				setError(data.error || data.stderr || "Unknown error from backend.");
				onUpdateChat([...newChat, { role: "assistant", content: `Error: ${data.error || data.stderr}` , ts: Date.now() }]);
			} else {
				onUpdateChat([...newChat, { role: "assistant", content: data.reply || data.summary, ts: Date.now() }]);
			}
		} catch (e) {
			setError("Failed to connect to backend.");
			onUpdateChat([...newChat, { role: "assistant", content: "Failed to connect to backend.", ts: Date.now() }]);
		}
		setMessage("");
		setLoading(false);
	};

	// Copy chat response
	const handleCopy = (text) => {
		navigator.clipboard.writeText(text);
	};

	// Download chat response
	const handleDownload = (text) => {
		const blob = new Blob([text], { type: "text/plain" });
		const url = URL.createObjectURL(blob);
		const a = document.createElement("a");
		a.href = url;
		a.download = "prajna-response.txt";
		a.click();
		URL.revokeObjectURL(url);
	};

	// File upload and analyze
	const handleFileChange = (e) => {
		const f = e.target.files[0];
		if (f && f.size <= 2 * 1024 * 1024) {
			setFile(f);
			setError("");
			handleAnalyzeFile(f);
		} else {
			setError("File too large (max 2MB)");
		}
	};

	const handleAnalyzeFile = async (f) => {
		if (!f) return;
		setLoading(true);
		setError("");
		const formData = new FormData();
		formData.append("file", f);
		try {
			const res = await fetch("http://localhost:5000/analyze-file", {
				method: "POST",
				headers: { 'X-Provider': selectedProvider || 'openai' },
				body: formData
			});
			const data = await res.json();
			const time = Date.now();
			if (!res.ok || data.result?.startsWith("Error")) {
				setError(data.result || "Unknown error analyzing file.");
				setFileResult("");
				onUpdateChat([...chat, { role: "file", filename: f.name, mimetype: f.type, size: f.size, ts: time }, { role: "assistant", content: `File analysis error: ${data.result}` , ts: Date.now()}]);
			} else {
				setFileResult(data.result);
				onUpdateChat([...chat, { role: "file", filename: f.name, mimetype: f.type, size: f.size, ts: time }, { role: "assistant", content: data.result, ts: Date.now() }]);
			}
		} catch (e) {
			setError("Failed to connect to backend.");
			setFileResult("");
			onUpdateChat([...chat, { role: "assistant", content: "Failed to connect to backend for file analysis.", ts: Date.now() }]);
		}
		setLoading(false);
	};

	const handleDownloadFileResult = () => {
		if (!fileResult) return;
		handleDownload(fileResult);
	};

	return (
		<div className="min-h-screen bg-gradient-to-b from-black via-gray-950 to-black text-green-300 p-6 md:p-10">
			<div className="max-w-[1400px] mx-auto">
				<div className="flex justify-between items-center mb-6">
					<h2 className="text-3xl md:text-4xl font-extrabold tracking-tight drop-shadow-[0_0_8px_rgba(16,185,129,0.30)]">Prajna Chat</h2>
					<div className="flex gap-2">
						<button className="px-4 py-2 bg-gray-800 hover:bg-gray-700 transition rounded-lg border border-gray-700" onClick={onSettingsClick}>Change Model</button>
						<button className="px-4 py-2 bg-red-800 hover:bg-red-700 transition rounded-lg border border-red-700" onClick={() => onResetAuth()}>Reset Auth</button>
					</div>
				</div>
				<div className="mb-4 text-sm">Splunk Status: <span className={splunkStatus === "Connected" ? "text-emerald-400" : "text-rose-400"}>{splunkStatus || "Checking..."}</span></div>

				{/* Chat history */}
				<div className="w-full h-[70vh] md:h-[72vh] bg-gray-900/70 rounded-2xl p-6 overflow-y-auto mb-4 border border-emerald-800/40 shadow-[0_0_30px_rgba(16,185,129,0.15)] backdrop-blur">
					{chat.map((msg, i) => (
						<div key={i} className={`mb-5 p-4 rounded-xl border transition ${msg.role === "user" ? "bg-gray-800/80 text-emerald-200 border-emerald-700/30" : msg.role === "file" ? "bg-gray-800/80 text-amber-200 border-amber-700/30" : "bg-gray-800/50 text-blue-200 border-blue-700/30"}`}>
							<div className="flex justify-between items-center">
								<b className="text-lg">{msg.role === "user" ? "You" : msg.role === "file" ? "File" : "Prajna"}:</b>
								{msg.role !== "file" && (
									<span>
										<button className="ml-2 px-3 py-1.5 bg-emerald-700/80 hover:bg-emerald-600 transition rounded text-white text-xs" onClick={() => handleCopy(msg.content)}>Copy</button>
										<button className="ml-2 px-3 py-1.5 bg-blue-700/80 hover:bg-blue-600 transition rounded text-white text-xs" onClick={() => handleDownload(msg.content)}>Download</button>
									</span>
								)}
							</div>
							<div className="mt-3 whitespace-pre-wrap text-base leading-relaxed">
								{msg.role === 'file' ? (
									<div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-amber-900/30 border border-amber-600/50 text-amber-200">
										<span className="text-sm font-semibold truncate max-w-[480px]" title={msg.filename}>{msg.filename}</span>
										<span className="text-xs opacity-80">{msg.mimetype || 'file'}</span>
										<span className="text-xs opacity-80">{Math.ceil((msg.size || 0)/1024)} KB</span>
									</div>
								) : (
									<span>{msg.content}</span>
								)}
							</div>
							<div className="mt-2 text-xs text-gray-400">{msg.ts ? new Date(msg.ts).toLocaleString() : ''}</div>
							{msg.imagePath && (
								<div className="mt-3">
									<img src={msg.imagePath} alt="tgpt generated" className="max-w-full rounded-xl shadow" />
								</div>
							)}
						</div>
					))}
					<div ref={chatEndRef} />
				</div>

				{/* Input and controls */}
				<div className="w-full flex flex-col gap-3">
					<div className="flex w-full items-center">
						<input
							type="text"
							className="flex-1 p-4 rounded-xl bg-gray-900 text-emerald-200 border-2 border-emerald-700/60 text-lg focus:outline-none focus:ring-2 focus:ring-emerald-500/60 transition"
							value={message}
							onChange={e => setMessage(e.target.value)}
							onKeyDown={e => e.key === "Enter" && sendMessage()}
							disabled={loading}
							placeholder="Type your message..."
						/>
						<button
							className="ml-3 px-8 py-4 bg-emerald-700 hover:bg-emerald-600 transition rounded-xl text-white text-lg shadow"
							onClick={sendMessage}
							disabled={loading || !message.trim()}
						>Send</button>
						<button
							className="ml-2 px-4 py-4 bg-blue-700 hover:bg-blue-600 transition rounded-full text-white text-lg flex items-center justify-center shadow"
							onClick={() => fileInputRef.current.click()}
							title="Analyze a file"
							style={{ minWidth: 56, minHeight: 56 }}
						>
							+
						</button>
						<input
							type="file"
							accept=".txt,.log,.csv,.json,.pdf,.docx,image/*"
							ref={fileInputRef}
							style={{ display: 'none' }}
							onChange={handleFileChange}
						/>
					</div>
					{selectedProvider === 'tgpt' && (
						<div className="w-full bg-gray-900/70 p-3 rounded-xl border border-blue-700/40 flex items-center gap-3">
							<span className="font-bold text-sm text-blue-200">tgpt:</span>
							<select className="p-2 rounded bg-gray-800 text-emerald-200 border border-emerald-700/50" value={tgptFlag} onChange={e => setTgptFlag(e.target.value)}>
								{tgptFeatures.map(f => <option key={f.value} value={f.value}>{f.label}</option>)}
							</select>
							{tgptFlag === 'img' && (
								<div className="flex items-center gap-2 flex-wrap">
									<input type="text" placeholder="out.png" className="p-2 rounded bg-gray-800 text-emerald-200 border border-emerald-700/50 w-40" onChange={e => setTgptOptions(o => ({ ...o, out: e.target.value }))} />
									<input type="number" placeholder="W" className="p-2 rounded bg-gray-800 text-emerald-200 border border-emerald-700/50 w-20" onChange={e => setTgptOptions(o => ({ ...o, width: e.target.value }))} />
									<input type="number" placeholder="H" className="p-2 rounded bg-gray-800 text-emerald-200 border border-emerald-700/50 w-20" onChange={e => setTgptOptions(o => ({ ...o, height: e.target.value }))} />
								</div>
							)}
						</div>
					)}
				</div>

				{error && <div className="text-rose-400 mt-3">{error}</div>}
			</div>
		</div>
	);
};

export default ChatInterface;
